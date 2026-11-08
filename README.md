# Hệ mã RSA - cài đặt từ đầu bằng Python

Cài đặt hoàn chỉnh hệ mã RSA cùng các thuật toán nền (Euclid mở rộng, nghịch đảo modulo,
bình phương và nhân, Miller-Rabin), **không dùng thư viện mật mã có sẵn cho phần lõi**.
Phiên bản thu nhỏ in từng bước theo **đúng ký hiệu và dạng bảng của bài giảng Chương 3**
(bảng Euclid mở rộng 10 cột, bảng nghịch đảo r0 r1 r2 q t0 t1, bảng bình phương và nhân i b_i c f,
Miller-Rabin với n - 1 = 2^k * q, KU = {e, n}, KR = {d, p, q}), chạy lại đúng mọi BTVD trong slide
và toàn bộ Bài tập luyện tập Chương 3 (17 ý, khớp 17/17 đáp án gợi ý của giảng viên).
Chỉ cần Python 3.8 trở lên, không cần cài thêm gói nào để chạy chương trình.
Hai gói `cryptography` và `sympy` là tùy chọn, chỉ dùng trong `tests/` để đối chiếu kết quả.

## 1. Cấu trúc mã nguồn

```
rsa_project/
├── cli.py                  Giao diện: menu tương tác + lệnh con (chỉ nhập/xuất, không có thuật toán)
├── rsa/                    PHẦN THUẬT TOÁN (tách riêng khỏi giao diện)
│   ├── number_theory.py    gcd, extended_gcd (bảng Euclid mở rộng), mod_inverse (bảng 6 cột), mod_pow (bình phương và nhân), euler_phi, crt
│   ├── primality.py        sàng Eratosthenes, chia thử, miller_rabin (1 vòng), is_probable_prime, generate_prime
│   ├── keygen.py           PublicKey / PrivateKey, keypair_from_primes (p, q cho trước), generate_keypair (n bit)
│   ├── rsa_core.py         RSAEP / RSADP (có và không CRT), RSASP1 / RSAVP1
│   ├── codec.py            I2OSP / OS2IP, đệm EME-PKCS1-v1_5 (RFC 8017 7.2), chia khối, mã hóa bytes / văn bản
│   ├── fileio.py           mã hóa / giải mã tệp, lưu / đọc khóa JSON
│   ├── toy.py              PHIÊN BẢN THU NHỎ: ví dụ trên lớp + các BTVD thuật toán nền, in mọi bước theo dạng slide
│   ├── attacks.py          minh họa 4 tấn công lên RSA sách giáo khoa
│   └── bench.py            đo thời gian theo độ dài khóa và kích thước dữ liệu
├── tests/                  BỘ KIỂM THỬ (unittest, 53 ca TC01..TC53)
│   ├── test_slide_examples.py  TÁI HIỆN ĐÚNG mọi ví dụ trong slide (từng ô của từng bảng)
│   ├── test_exercises.py       Bài tập luyện tập Chương 3 + Chương 4 Bài 10: khớp đáp án gợi ý
│   ├── test_number_theory.py   đối chiếu math.gcd, pow(b, e, m), pow(a, -1, m)
│   ├── test_primality.py       đối chiếu sàng Eratosthenes, số Mersenne / Carmichael, sympy (tùy chọn)
│   ├── test_rsa.py             ví dụ thu nhỏ, vòng tròn mã hóa - giải mã, tệp, đệm, lưu khóa
│   ├── test_compare_lib.py     TEST VECTOR CHUẨN Wycheproof + thư viện cryptography (OpenSSL)
│   └── vectors/wycheproof_rsa_pkcs1_2048.json
├── data/sample.txt, data/sample.png   dữ liệu thật để demo (văn bản tiếng Việt 1.5 KB, ảnh PNG 11.6 KB)
├── tools/make_sample_image.py         sinh lại ảnh mẫu (chỉ dùng zlib / struct)
├── keys/                   khóa sinh ra khi demo (key.json, key.pub.json)
└── out/                    tệp bản mã / bản giải mã sinh ra khi demo
```

Mọi hàm lõi nhận tham số `trace` tùy chọn: phiên bản thu nhỏ bật `trace` để lấy từng bước,
phiên bản đầy đủ tắt để chạy nhanh. **Hai phiên bản dùng chung đúng một mã nguồn thuật toán.**

## 2. Cách chạy

```bash
python cli.py                                   # menu tương tác (12 chức năng)

# hoặc lệnh con (tiện khi demo / quay video dự phòng)
python cli.py toy --preset lop                  # phiên bản thu nhỏ với BTVD trên lớp (p=17, q=11, e=7, M=88)
python cli.py toy --preset lop --text HELLO     # thêm mã hóa chuỗi từng ký tự
python cli.py toy --p 61 --q 53 --e 17 --m 65   # tự nhập p, q, e, M
python cli.py toy --preset lop --save out/buoc.txt   # lưu toàn bộ bước ra tệp
python cli.py slide --name all                  # chạy lại mọi BTVD thuật toán nền trong slide (gcd, exgcd, inv1, inv2, modpow, mr)
python cli.py gcd --a 4864 --b 3458             # Euclid, từng dòng a = q*b + r            (slide 14)
python cli.py exgcd --a 4864 --b 3458           # bảng Euclid mở rộng 10 cột               (slide 16)
python cli.py inverse --a 173 --n 1024          # bảng nghịch đảo r0 r1 r2 q t0 t1           (slide 21)
python cli.py modpow --a 7 --k 560 --n 561      # bảng bình phương và nhân i b_i c f         (slide 24)
python cli.py prime --n 561 --bases 2,7         # Miller-Rabin từng bước                   (slide 30)
python cli.py exercise --name all               # Bài tập luyện tập Chương 3: chạy từng bài, đối chiếu đáp án gợi ý
python cli.py crt --res 1,4,6 --mods 5,7,11     # định lý phần dư Trung Hoa theo công thức slide 31
python cli.py phi --n 144                       # hàm Ơle qua phân tích thừa số
python cli.py sign --p 13 --q 23 --e 17 --m 42  # chữ ký RSA: ký rồi kiểm chứng; thêm --s 191 để kiểm một cặp (M, S)
python cli.py keygen --bits 2048 --out keys/key.json
python cli.py encrypt --key keys/key.json --text "xin chào"       # mã hóa rồi giải mã lại
python cli.py roundtrip --key keys/key.json --in data/sample.png  # mã hóa tệp -> giải mã -> so sánh từng byte
python cli.py encrypt-file --key keys/key.pub.json --in data/sample.txt --out out/sample.txt.enc
python cli.py decrypt-file --key keys/key.json --in out/sample.txt.enc --out out/sample.dec.txt --original data/sample.txt
python cli.py test                              # 40 ca kiểm thử + đối chiếu, in kết quả đối chiếu
python cli.py bench --bits 1024                 # đo thời gian
python cli.py attack                            # minh họa tấn công
```

Bộ kiểm thử cũng chạy được bằng `python -m unittest discover -v tests`.

## 3. Phiên bản thu nhỏ: tái hiện ví dụ trên lớp

Preset `lop` trong `rsa/toy.py` là BTVD RSA của bài giảng (slide 43-44): p = 17, q = 11, M = 88
-> n = 187, Φ(n) = 160, e = 7, d = 23, KU = {7, 187}, KR = {23, 17, 11}, C = 88^7 mod 187 = 11,
M = 11^23 mod 187 = 88, giải mã nhanh bằng định lý phần dư Trung Hoa: 11^23 mod 11 = 0,
11^23 mod 17 = 3, 11^-1 mod 17 = 14, c = 11*14 = 154, M = 3*154 mod 187 = 462 mod 187 = 88.
Có thêm preset `wikipedia` (p = 61, q = 53, e = 17, M = 65) và nhập tay p, q, e, M bất kỳ.

Các bước in ra (ký hiệu đúng như slide):
1. Miller-Rabin cho p, q (slide 30): n - 1 = 2^k * q; a^q mod n; j = 0..k-1: a^(2^j * q) mod n; kết luận.
2. n = p*q, Φ(n) = (p-1)*(q-1).
3. Euclid kiểm tra GCD(e, Φ(n)) = 1 (slide 14): từng dòng a = q*b + r.
4. d = e^-1 mod Φ(n) bằng bảng 6 cột Dòng, r0, r1, r2, q, t0, t1 (slide 18-21); kiểm tra d*e = 1 mod Φ(n).
5. KU = {e, n}, KR = {d, p, q}.
6. Mã hóa C = M^e mod n bằng bảng i, b_i, c, f (slide 24) kèm cách tính từng ô.
7. Giải mã M = C^d mod n bằng bảng như trên; thêm giải mã nhanh bằng định lý phần dư Trung Hoa
   theo công thức slide 31 và 44 (a1, a2, c1, c2, M = (a1*c1 + a2*c2) mod n).
8. (tùy chọn) mã hóa chuỗi từng ký tự rồi giải mã lại.

Các BTVD về thuật toán nền trong slide cũng chạy lại được (menu 11 hoặc `python cli.py slide`):
GCD(4864, 3458) = 38; bảng Euclid mở rộng 4864*32 + 3458*(-45) = 38; 25^-1 mod 101 = 97;
173^-1 mod 1024 = 805; 7^560 mod 561 = 1 (bảng c, f); Miller-Rabin cho 561 (Fermat bị lừa, Miller-Rabin phát hiện hợp số).
Ca kiểm thử TC41-TC47 so từng ô của các bảng này với slide.

Bài tập luyện tập Chương 3 (menu 12 hoặc `python cli.py exercise`): Bài 2 (Euclid, Euclid mở rộng), Bài 3
(bảng nghịch đảo, phương trình đồng dư, trường hợp không khả nghịch), Bài 4 (bình phương và nhân), Bài 5
(hàm Ơle, Ferma), Bài 6 (định lý phần dư Trung Hoa), Bài 8 (RSA p = 13, q = 23, e = 17: d = 233, C = 289),
Bài 12 (chữ ký RSA: S = 191, cặp (50, 191) không hợp lệ) và Chương 4 Bài 10 (p = 13, q = 19, b = 5: a = 173,
y = 53). Chương trình in lời giải từng bước và dòng "Đối chiếu đáp án gợi ý: KHỚP"; ca kiểm thử TC48-TC53
khóa các con số này.

## 4. Phiên bản đầy đủ

- Sinh p, q ngẫu nhiên bằng `secrets.SystemRandom` (nguồn ngẫu nhiên hệ điều hành, thư viện chuẩn),
  mỗi số bits/2 bit, đặt hai bit cao nhất để n có đúng số bit; kiểm tra bằng chia thử + 20 vòng Miller-Rabin.
- e = 65537; d bằng Euclid mở rộng; giải mã mặc định dùng CRT (nhanh hơn ~3.5 lần, xem bench).
- Dữ liệu bất kỳ (văn bản UTF-8, tệp nhị phân) được chia khối k - 11 byte, đệm PKCS#1 v1.5
  (0x00 0x02 PS 0x00 M, PS ngẫu nhiên khác 0, >= 8 byte) rồi mã hóa từng khối thành k byte.
  Nhờ đệm ngẫu nhiên, cùng một bản rõ cho bản mã khác nhau mỗi lần.
- Chế độ `raw` (không đệm) chỉ để minh họa RSA sách giáo khoa và các tấn công.
- Giải mã sai khóa / đệm sai ném đúng một ngoại lệ `PaddingError` (không phân biệt loại lỗi, tránh padding oracle).

## 5. Kiểm thử và đối chiếu

| Nhóm | Ca | Đối chiếu với |
|---|---|---|
| Ví dụ trên lớp | TC41-TC47 | từng ô của các bảng và kết quả trong slide Chương 3 (slide 14, 16, 20, 21, 24, 30, 43, 44) |
| Bài tập luyện tập | TC48-TC53 | đáp án gợi ý của giảng viên cho Chương 3 Bài 2, 3, 4, 5, 6, 8, 12 và Chương 4 Bài 10 |
| Số học | TC01-TC12 | `math.gcd`, `pow(b, e, m)`, `pow(a, -1, m)` của Python; ví dụ giáo trình |
| Nguyên tố | TC13-TC20 | sàng Eratosthenes (mọi n < 100000), số nguyên tố Mersenne, số Carmichael, `sympy.isprime` (nếu cài) |
| RSA | TC21-TC32 | ví dụ trên lớp (p=17, q=11) và Wikipedia; vòng tròn số / văn bản / tệp; đệm; lưu khóa |
| Test vector chuẩn | TC33-TC36 | **Project Wycheproof** (Google) `rsa_pkcs1_2048_test.json`: 10 ca giải mã hợp lệ phải khớp bản rõ từng byte, 5 ca đệm sai phải bị từ chối |
| Thư viện chuẩn | TC37-TC40 | **cryptography (OpenSSL)**: thư viện chấp nhận khóa của nhóm; thư viện mã hóa - nhóm giải mã và ngược lại; khóa OpenSSL chạy trên mã của nhóm |

Kết quả đối chiếu được in ra dòng `[ĐỐI CHIẾU] ...` khi chạy `python cli.py test`.
Cài gói tùy chọn để chạy đủ 53 ca: `pip install cryptography sympy` (thiếu thì các ca đó được bỏ qua, không lỗi).

## 6. Đo thời gian (tham khảo, Python 3.13, 1 lõi CPU)

| Khóa | Sinh khóa | Giải mã CRT 10 KB | Giải mã thường 10 KB |
|---|---|---|---|
| 1024 bit | ~0.06 s | ~0.12 s | ~0.34 s |
| 2048 bit | ~0.3-0.7 s | ~0.3 s | ~1.1 s |

Mã hóa nhanh hơn giải mã nhiều lần vì e = 65537 chỉ có 17 bit. `python cli.py bench` in bảng đầy đủ
theo kích thước 1 KB / 10 KB / 100 KB và so tốc độ `mod_pow` tự cài với `pow()` của Python.

## 7. Minh họa tấn công (`python cli.py attack`)

1. Phân tích n: khóa thu nhỏ n = 187 bị phá bằng chia thử; khóa 256 bit nhưng p, q gần nhau bị phá bằng
   Fermat sau 1 vòng; p, q ngẫu nhiên độc lập thì Fermat thất bại.
2. e = 3, không đệm, bản rõ ngắn: căn bậc ba nguyên của C cho ngay M; có đệm PKCS#1 thì không.
3. Chung modulus: hai bản mã của cùng M với e1, e2 -> Euclid mở rộng khôi phục M không cần d.
4. Tính nhân (malleability): C' = C * r^e mod n giải mã ra r * M.

## 8. Kịch bản demo 5-7 phút

1. (2 phút) `python cli.py toy --preset lop`: chỉ vào từng bước Miller-Rabin, bảng nghịch đảo tìm d = 23,
   bảng bình phương và nhân ra C = 11 rồi M = 88, phần CRT khớp slide 44. Nếu còn thời gian:
   `python cli.py slide --name modpow` (bảng 7^560 mod 561 giống hệt slide 24).
2. (1.5 phút) Menu 2 -> sinh khóa 2048 bit; menu 5 -> nhập một câu tiếng Việt, xem bản mã hex, giải mã lại đúng.
3. (1 phút) Menu 7 -> `data/sample.png`: bản mã khác hẳn, giải mã ra `out/sample.dec.png` giống hệt từng byte
   (mở ảnh lên cho lớp xem).
4. (1 phút) Menu 8 -> bộ kiểm thử: 53 ca, các dòng `[ĐỐI CHIẾU]` với Wycheproof và OpenSSL.
5. (1 phút) Menu 10 -> tấn công (hoặc menu 9 -> đo thời gian) tùy thời gian còn lại.

Video dự phòng: chạy các lệnh con ở mục 2 và quay màn hình; `--save` lưu sẵn toàn bộ bước của
phiên bản thu nhỏ ra tệp văn bản để chiếu nếu máy lỗi.
