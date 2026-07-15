#include <inttypes.h>
#include <mayo.h>

#include <aes_ctr.h>
#include <arithmetic.h>
#include <fips202.h>
#include <mem.h>
#include <randombytes.h>
#include <simple_arithmetic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define MAX_UNK 7000
#define MAX_EQ 6000
#define PK_PRF AES_128_CTR

// ---------------- GF(16) arithmetic ----------------

static unsigned char gf_add(unsigned char a, unsigned char b) {
  return (a ^ b) & 0xF;
}

static unsigned char gf_mul(unsigned char a, unsigned char b) {
  unsigned char p;
  p = (a & 1) * b;
  p ^= (a & 2) * b;
  p ^= (a & 4) * b;
  p ^= (a & 8) * b;

  // reduce mod x^4 + x + 1
  unsigned char top_p = p & 0xf0;
  unsigned char out = (p ^ (top_p >> 4) ^ (top_p >> 3)) & 0x0f;
  return out;
}

static unsigned char gf_inv(unsigned char a) {
  unsigned char a2 = gf_mul(a, a);
  unsigned char a4 = gf_mul(a2, a2);
  unsigned char a8 = gf_mul(a4, a4);
  unsigned char a6 = gf_mul(a2, a4);
  unsigned char a14 = gf_mul(a8, a6);

  return a14;
}

// Gaussian Elimination GF(16)

static unsigned char extract_m_element(const uint64_t *vec, int ell,
                                       int m_vec_limbs) {
  int limb = ell / 16;
  int pos = ell % 16;

  uint64_t w = vec[limb];

  int base = pos * 4;

  unsigned char val = 0;

  if (w & (1ULL << (base + 0)))
    val |= 1;

  if (w & (1ULL << (base + 1)))
    val |= 2;

  if (w & (1ULL << (base + 2)))
    val |= 4;

  if (w & (1ULL << (base + 3)))
    val |= 8;

  return val;
}

static void reconstruct_full_P3(const mayo_params_t *p, const uint64_t *epk,
                                uint64_t *P3_full) {
  int o = PARAM_o(p);
  int m_vec_limbs = PARAM_m_vec_limbs(p);

  const uint64_t *P3_upper = epk + PARAM_P1_limbs(p) + PARAM_P2_limbs(p);

  int idx = 0;

  for (int r = 0; r < o; r++) {
    for (int c = r; c < o; c++) {
      const uint64_t *src = P3_upper + m_vec_limbs * idx;

      for (int l = 0; l < m_vec_limbs; l++) {
        P3_full[m_vec_limbs * (r * o + c) + l] = src[l];
        if (r != c)
          P3_full[m_vec_limbs * (c * o + r) + l] = src[l];
      }

      idx++;
    }
  }
}

static int solve_linear_system(unsigned char *A, unsigned char *b,
                               unsigned char *x, int rows, int cols) {
  unsigned char *M = calloc(rows * (cols + 1), 1);

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++)
      M[i * (cols + 1) + j] = A[i * cols + j];
    M[i * (cols + 1) + cols] = b[i];
  }

  int rank = 0;

  for (int col = 0; col < cols && rank < rows; col++) {
    int pivot = -1;
    for (int row = rank; row < rows; row++) {
      if (M[row * (cols + 1) + col] != 0) {
        pivot = row;
        break;
      }
    }

    if (pivot == -1)
      continue;

    if (pivot != rank) {
      for (int j = 0; j <= cols; j++) {
        unsigned char tmp = M[pivot * (cols + 1) + j];
        M[pivot * (cols + 1) + j] = M[rank * (cols + 1) + j];
        M[rank * (cols + 1) + j] = tmp;
      }
    }

    unsigned char inv = gf_inv(M[rank * (cols + 1) + col]);

    for (int j = col; j <= cols; j++)
      M[rank * (cols + 1) + j] = gf_mul(M[rank * (cols + 1) + j], inv);

    for (int row = 0; row < rows; row++) {
      if (row != rank && M[row * (cols + 1) + col] != 0) {
        unsigned char factor = M[row * (cols + 1) + col];

        for (int j = col; j <= cols; j++) {
          M[row * (cols + 1) + j] =
              gf_add(M[row * (cols + 1) + j],
                     gf_mul(factor, M[rank * (cols + 1) + j]));
        }
      }
    }

    rank++;
  }

  memset(x, 0, cols);

  for (int i = 0; i < rank; i++) {
    int lead = -1;
    for (int j = 0; j < cols; j++) {
      if (M[i * (cols + 1) + j] == 1) {
        lead = j;
        break;
      }
    }

    if (lead != -1)
      x[lead] = M[i * (cols + 1) + cols];
  }

  free(M);
  return rank;
}

static void verify_fault_equation(const mayo_params_t *p, const uint64_t *epk,
                                  const sk_t *esk) {
  int v = PARAM_v(p);
  int o = PARAM_o(p);
  int m = PARAM_m(p);
  int m_vec_limbs = PARAM_m_vec_limbs(p);

  uint64_t *P2 = (uint64_t *)(epk + PARAM_P1_limbs(p));

  uint64_t *P3_full = calloc(o * o * m_vec_limbs, sizeof(uint64_t));

  reconstruct_full_P3(p, epk, P3_full);

  printf("\nVerifying P3 = O^T P2 + P2^T O\n");

  for (int ell = 0; ell < m; ell++) {
    for (int i = 0; i < o; i++) {
      for (int j = i; j < o; j++) {
        unsigned char rhs = 0;

        for (int k = 0; k < v; k++) {
          unsigned char Oki = esk->O[k * o + i] & 0xF;

          unsigned char Okj = esk->O[k * o + j] & 0xF;

          const uint64_t *p2_kj = P2 + m_vec_limbs * (k * o + j);

          const uint64_t *p2_ki = P2 + m_vec_limbs * (k * o + i);

          unsigned char p2kj = extract_m_element(p2_kj, ell, m_vec_limbs);

          unsigned char p2ki = extract_m_element(p2_ki, ell, m_vec_limbs);

          if (i == j) {
            rhs ^= gf_mul(Oki, p2kj);
          } else {
            rhs ^= gf_mul(Oki, p2kj);
            rhs ^= gf_mul(Okj, p2ki);
          }
        }

        const uint64_t *p3_entry = P3_full + m_vec_limbs * (i * o + j);

        unsigned char lhs = extract_m_element(p3_entry, ell, m_vec_limbs);

        if (lhs != rhs) {
          printf("Mismatch at poly %d, (%d,%d)\n", ell, i, j);
          printf("Stored P3 = %x, Computed RHS = %x\n", lhs, rhs);

          free(P3_full);
          return;
        }
      }
    }
  }

  printf("Equation holds for all entries.\n");

  free(P3_full);
}

static inline void compute_P3_correct(const mayo_params_t *p,
                                      const uint64_t *P1, uint64_t *P2,
                                      const unsigned char *O, uint64_t *P3) {
  const int m_vec_limbs = PARAM_m_vec_limbs(p);
  const int param_v = PARAM_v(p);
  const int param_o = PARAM_o(p);

  // compute P1*O + P2
  P1_times_O(p, P1, O, P2);

  // compute P3 = O^t * (P1*O + P2)
  mul_add_mat_trans_x_m_mat(m_vec_limbs, O, P2, P3, param_v, param_o, param_o);
}

static void pack_m_vecs(const uint64_t *in, unsigned char *out, int vecs,
                        int m) {
  const int m_vec_limbs = (m + 15) / 16;
  unsigned char *_in = (unsigned char *)in;
  for (int i = 0; i < vecs; i++) {
    memmove(out + (i * m / 2), _in + i * m_vec_limbs * sizeof(uint64_t), m / 2);
  }
}

// ---------------- Rebuild public key from recovered O ----------------
static void dump_hex(const char *label, const unsigned char *buf, size_t len) {
  printf("%s (%zu bytes):\n", label, len);

  for (size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);

    if ((i + 1) % 32 == 0)
      printf("\n");
    else if ((i + 1) % 2 == 0)
      printf(" ");
  }

  if (len % 32)
    printf("\n");
}

static unsigned char *rebuild_pk_from_recovered_O(
    const mayo_params_t *p, const uint64_t *epk, const sk_t *esk,
    const unsigned char
        *recovered_x, // laid out as x[i * v + k], i in [0,o), k in [0,v)
    const unsigned char *real_pk, int real_pk_len, unsigned char *seed_pk) {
  int v = PARAM_v(p);
  int o = PARAM_o(p);
  int m_vec_limbs = PARAM_m_vec_limbs(p);

  int param_pk_seed_bytes = PARAM_pk_seed_bytes(p);
  int param_P1_limbs = PARAM_P1_limbs(p);
  int param_P2_limbs = PARAM_P2_limbs(p);
  int param_P3_limbs = PARAM_P3_limbs(p);

  // Re-layout recovered oil matrix into O[k * o + i] form, matching esk->O /
  // sk_t, which is what compute_P3 / P1_times_O expect.
  unsigned char *O_rec = calloc((size_t)v * o, 1);
  for (int i = 0; i < o; i++)
    for (int k = 0; k < v; k++)
      O_rec[k * o + i] = recovered_x[i * v + k] & 0xF;

  int o_mismatches = 0;
  int first_o_mismatch = -1;
  for (int k = 0; k < v; k++) {
    for (int i = 0; i < o; i++) {
      int idx = k * o + i;
      unsigned char rec_val = O_rec[idx] & 0xF;
      unsigned char real_val = esk->O[idx] & 0xF;
      if (rec_val != real_val) {
        o_mismatches++;
        if (first_o_mismatch == -1)
          first_o_mismatch = idx;
      }
    }
  }
  if (o_mismatches == 0)
    printf("O_rec matches esk->O exactly (%d entries checked).\n", v * o);
  else
    printf("O_rec MISMATCH: %d / %d entries differ, first at index %d "
           "(k=%d,i=%d) rec=0x%x real=0x%x\n",
           o_mismatches, v * o, first_o_mismatch, first_o_mismatch / o,
           first_o_mismatch % o, O_rec[first_o_mismatch] & 0xF,
           esk->O[first_o_mismatch] & 0xF);

  // ---- Single contiguous P buffer, exactly like mayo_keypair_compact ----
  uint64_t *P =
      calloc((size_t)param_P1_limbs + param_P2_limbs, sizeof(uint64_t));
  memcpy(P, epk, ((size_t)param_P1_limbs + param_P2_limbs) * sizeof(uint64_t));

  uint64_t *P1 = P;
  uint64_t *P2 = P + param_P1_limbs;

  int p1_mismatches = 0;
  for (int i = 0; i < param_P1_limbs; i++)
    if (P1[i] != epk[i]) {
      p1_mismatches++;
      break;
    }
  printf("P1 slice check: %s\n", p1_mismatches == 0 ? "OK" : "MISMATCH");

  int p2_mismatches = 0;
  for (int i = 0; i < param_P2_limbs; i++)
    if (P2[i] != epk[param_P1_limbs + i]) {
      p2_mismatches++;
      break;
    }
  printf("P2 pre-mutation check: %s\n", p2_mismatches == 0 ? "OK" : "MISMATCH");

  uint64_t P3[O_MAX * O_MAX * M_VEC_LIMBS_MAX] = {0};

  // compute P3 (modifies P2 in the process) -- same call as
  // mayo_keypair_compact
  compute_P3_correct(p, P1, P2, O_rec, P3);
  unsigned char *rebuilt_pk = calloc(1, real_pk_len);

  memcpy(rebuilt_pk, real_pk, param_pk_seed_bytes);
  memcpy(seed_pk, real_pk, param_pk_seed_bytes);

  uint64_t P3_upper[P3_LIMBS_MAX];
  // memset(P3_upper, 0, sizeof(P3_upper));
  m_upper(p, P3, P3_upper, o);
  pack_m_vecs(P3_upper, rebuilt_pk + param_pk_seed_bytes,
              param_P3_limbs / m_vec_limbs, PARAM_m(p));
  //   dump_hex("REBUILT_PK", rebuilt_pk, real_pk_len);
  //   dump_hex("REBUILT_SEED_PK", rebuilt_pk, param_pk_seed_bytes);

  //   dump_hex("REBUILT_ENCODED_P3", rebuilt_pk + param_pk_seed_bytes,
  //            real_pk_len - param_pk_seed_bytes);

  dump_hex("CORRECTED_KEY", rebuilt_pk, real_pk_len);

  // ---- Direct comparison against the genuine P3_upper already in epk ----
  const uint64_t *genuine_P3_upper = epk + param_P1_limbs + param_P2_limbs;
  int p3_upper_limb_mismatches = 0;
  int first_p3_upper_mismatch = -1;
  for (int i = 0; i < param_P3_limbs; i++) {
    if (P3_upper[i] != genuine_P3_upper[i]) {
      p3_upper_limb_mismatches++;
      if (first_p3_upper_mismatch == -1)
        first_p3_upper_mismatch = i;
    }
  }
  if (p3_upper_limb_mismatches == 0)
    printf("P3_upper (pre-pack) matches genuine epk P3_upper exactly (%d limbs "
           "checked).\n",
           param_P3_limbs);
  else
    printf(
        "P3_upper (pre-pack) MISMATCH: %d / %d limbs differ, first at limb %d "
        "(computed=0x%016" PRIx64 ", genuine=0x%016" PRIx64 ")\n",
        p3_upper_limb_mismatches, param_P3_limbs, first_p3_upper_mismatch,
        P3_upper[first_p3_upper_mismatch],
        genuine_P3_upper[first_p3_upper_mismatch]);

  //   printf("\n==============================\n");
  //   printf("Recomputing public key from recovered O\n");
  //   printf("==============================\n");

  int diff = memcmp(rebuilt_pk, real_pk, real_pk_len);

  if (diff == 0) {
    printf("SUCCESS: rebuilt public key matches the real public key.\n");
  } else {
    printf("FAIL: rebuilt public key differs from the real public key.\n");

    int first_mismatch = -1;
    for (int i = 0; i < real_pk_len; i++) {
      if (rebuilt_pk[i] != real_pk[i]) {
        first_mismatch = i;
        break;
      }
    }
    printf("First differing byte at offset %d (real=0x%02x, rebuilt=0x%02x)\n",
           first_mismatch, real_pk[first_mismatch], rebuilt_pk[first_mismatch]);
  }

  free(O_rec);
  free(P);
  // free(rebuilt_pk);
  return rebuilt_pk;
}

// ---------------- Fault Simulation ----------------

static void example_fault_P3_OtP2(const mayo_params_t *p) {
  printf("Fault sim: P3 = O^T P2\n");

  int v = PARAM_v(p);
  int o = PARAM_o(p);
  int m = PARAM_m(p);
  int m_vec_limbs = PARAM_m_vec_limbs(p);

  unsigned char *pk = calloc(1, PARAM_cpk_bytes(p));
  unsigned char *sk = calloc(1, PARAM_csk_bytes(p));
  sk_t *esk = calloc(1, sizeof(sk_t));
  uint64_t *epk = calloc(1, sizeof(pk_t));

  mayo_keypair(p, pk, sk);
  mayo_expand_sk(p, sk, esk);
  mayo_expand_pk(p, pk, epk);

  uint64_t *P3_upper = (uint64_t *)(pk + PARAM_pk_seed_bytes(p));
  if (memcmp(P3_upper, epk + PARAM_P1_limbs(p) + PARAM_P2_limbs(p),
             PARAM_P3_bytes(p))) {
    printf(" P3 matches \n");
  }
  printf("P3_upper = 0x%016" PRIx64 "\n", *P3_upper);

  verify_fault_equation(p, epk, esk);

  uint64_t *P2 = epk + PARAM_P1_limbs(p);
  uint64_t *P3_full = calloc(o * o * m_vec_limbs, sizeof(uint64_t));

  reconstruct_full_P3(p, epk, P3_full);
  printf("P3_full = 0x%016" PRIx64 "\n", *P3_full);

  int unknowns = v * o;
  int equations = m * (o * (o + 1) / 2);

  printf("SOlving %d equations in %d variables : \n", equations, unknowns);

  unsigned char *A = calloc(equations * unknowns, 1);
  unsigned char *b = calloc(equations, 1);
  unsigned char *x = calloc(unknowns, 1);

  int eq = 0;

  for (int ell = 0; ell < m; ell++) {
    for (int i = 0; i < o; i++) {
      for (int j = i; j < o; j++) {
        const uint64_t *p3_entry = P3_full + m_vec_limbs * (i * o + j);

        b[eq] = extract_m_element(p3_entry, ell, m_vec_limbs);

        for (int k = 0; k < v; k++) {
          int idx_i = i * v + k;
          int idx_j = j * v + k;

          const uint64_t *p2_kj = P2 + m_vec_limbs * (k * o + j);

          const uint64_t *p2_ki = P2 + m_vec_limbs * (k * o + i);

          A[eq * unknowns + idx_i] =
              gf_add(A[eq * unknowns + idx_i],
                     extract_m_element(p2_kj, ell, m_vec_limbs));

          if (i != j)
            A[eq * unknowns + idx_j] =
                gf_add(A[eq * unknowns + idx_j],
                       extract_m_element(p2_ki, ell, m_vec_limbs));
        }

        eq++;
      }
    }
  }
  int rank = solve_linear_system(A, b, x, equations, unknowns);

  printf("System rank = %d\n", rank);

  printf("\n==============================\n");
  printf("Recovered Oil Matrix (column-wise)\n");
  printf("==============================\n");

  for (int i = 0; i < o; i++) {
    printf("\nColumn %d:\n", i);
    for (int k = 0; k < v; k++) {
      printf("%x ", x[i * v + k] & 0xF);
    }
    printf("\n");
  }

  printf("\n==============================\n");
  printf("Real Oil Matrix (column-wise)\n");
  printf("==============================\n");

  for (int i = 0; i < o; i++) {
    printf("\nColumn %d:\n", i);
    for (int k = 0; k < v; k++) {
      printf("%x ", esk->O[k * o + i] & 0xF);
    }
    printf("\n");
  }

  // Verification
  int ok = 1;

  for (int i = 0; i < o; i++) {
    for (int k = 0; k < v; k++) {
      unsigned char rec = x[i * v + k] & 0xF;

      unsigned char real = esk->O[k * o + i] & 0xF;

      if (rec != real) {
        ok = 0;
        break;
      }
    }
  }

  printf("\n==============================\n");
  if (ok)
    printf("SUCCESS: Oil fully recovered\n");
  else
    printf("FAIL: Oil mismatch\n");
  printf("==============================\n");

  // Now recompute P3 from the recovered O and rebuild cpk, to check that
  // a fresh keypair_compact-style packing reproduces the real public key.
  int param_pk_seed_bytes = PARAM_pk_seed_bytes(p);

  unsigned char *seed_pk = calloc(param_pk_seed_bytes, 1);
  unsigned char *rebuilt_pk = rebuild_pk_from_recovered_O(
      p, epk, esk, x, pk, PARAM_cpk_bytes(p), seed_pk);

  unsigned char *O_rec = calloc((size_t)v * o, 1);
  for (int i = 0; i < o; i++)
    for (int k = 0; k < v; k++)
      O_rec[k * o + i] = x[i * v + k] & 0xF;

  //   dump_hex("SEED_PK", seed_pk, param_pk_seed_bytes);
  unsigned char *cpk = calloc(PARAM_cpk_bytes(p), 1);
  {
    // uint64_t P[P1_LIMBS_MAX + P2_LIMBS_MAX];

    int param_P1_limbs = PARAM_P1_limbs(p);
    uint64_t *P1 = epk;
    uint64_t *P2 = epk + param_P1_limbs;
    uint64_t P3[O_MAX * O_MAX * M_VEC_LIMBS_MAX] = {0};
    const int param_o = PARAM_o(p);
    const int param_m = PARAM_m(p);
    int param_P3_limbs = PARAM_P3_limbs(p);

    // expand_P1_P2(p, P, seed_pk);
    compute_P3_correct(p, P1, P2, O_rec, P3);

    // store seed_pk in cpk
    memcpy(cpk, seed_pk, param_pk_seed_bytes);

    uint64_t P3_upper[P3_LIMBS_MAX];

    m_upper(p, P3, P3_upper, param_o);
    pack_m_vecs(P3_upper, cpk + param_pk_seed_bytes,
                param_P3_limbs / m_vec_limbs, param_m);

    // dump_hex("CORRECTED_pk_seed", cpk, param_pk_seed_bytes);

    // dump_hex("CORRECTED_ENCODED_P3", cpk + param_pk_seed_bytes,
    //          PARAM_cpk_bytes(p) - param_pk_seed_bytes);

    dump_hex("ACTUAL_KEY", cpk, PARAM_cpk_bytes(p));
  }
  size_t msglen = 32;
  size_t smlen = PARAM_sig_bytes(p) + msglen;

  unsigned char msg[32] = {0x42};
  unsigned char *sig = calloc(smlen, 1);

  int res = mayo_sign(p, sig, &smlen, msg, msglen, sk);

  printf("\n===== Signature Verification =====\n");

  res = mayo_verify(p, msg, msglen, sig, cpk);
  printf("Verify with recomputed cpk   : %s\n",
         res == MAYO_OK ? "PASS" : "FAIL");

  res = mayo_verify(p, msg, msglen, sig, rebuilt_pk);
  printf("Verify with rebuilt pk       : %s\n",
         res == MAYO_OK ? "PASS" : "FAIL");
  free(sig);
  free(pk);
  mayo_secure_free(sk, PARAM_csk_bytes(p));
  free(esk);
  free(epk);
  free(P3_full);
  free(A);
  free(b);
  free(x);
}

int main(void) { example_fault_P3_OtP2(NULL); }