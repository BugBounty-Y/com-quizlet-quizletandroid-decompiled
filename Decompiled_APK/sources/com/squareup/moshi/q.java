package com.squareup.moshi;

import java.io.EOFException;
import java.io.IOException;
import java.math.BigDecimal;
import kotlin.text.Charsets;
import okio.C5091h;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public final class q extends p {
    public static final okio.k n;
    public static final okio.k o;
    public static final okio.k p;
    public static final okio.k q;
    public static final okio.k r;
    public final InterfaceC5093j g;
    public final C5091h h;
    public int i;
    public long j;
    public int k;
    public String l;
    public v m;

    static {
        okio.k kVar = okio.k.d;
        n = com.quizlet.quizletandroid.ui.common.images.capture.b.i("'\\");
        o = com.quizlet.quizletandroid.ui.common.images.capture.b.i("\"\\");
        p = com.quizlet.quizletandroid.ui.common.images.capture.b.i("{}[]:, \n\t\r\f/\\;#=");
        q = com.quizlet.quizletandroid.ui.common.images.capture.b.i("\n\r");
        r = com.quizlet.quizletandroid.ui.common.images.capture.b.i("*/");
    }

    public q(InterfaceC5093j interfaceC5093j) {
        this.i = 0;
        this.g = interfaceC5093j;
        this.h = interfaceC5093j.c();
        c0(6);
    }

    @Override // com.squareup.moshi.p
    public final String B() throws EOFException, JsonEncodingException {
        String strW0;
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 14) {
            strW0 = x0();
        } else if (iR0 == 13) {
            strW0 = w0(o);
        } else if (iR0 == 12) {
            strW0 = w0(n);
        } else {
            if (iR0 != 15) {
                throw new JsonDataException("Expected a name but was " + Q() + " at path " + j());
            }
            strW0 = this.l;
            this.l = null;
        }
        this.i = 0;
        this.c[this.a - 1] = strW0;
        return strW0;
    }

    @Override // com.squareup.moshi.p
    public final void C() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 7) {
            this.i = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return;
        }
        throw new JsonDataException("Expected null but was " + Q() + " at path " + j());
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x00b9  */
    @Override // com.squareup.moshi.p
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final okio.InterfaceC5093j D() throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 216
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.squareup.moshi.q.D():okio.j");
    }

    @Override // com.squareup.moshi.p
    public final String P() throws EOFException, JsonEncodingException {
        String strC0;
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 10) {
            strC0 = x0();
        } else if (iR0 == 9) {
            strC0 = w0(o);
        } else if (iR0 == 8) {
            strC0 = w0(n);
        } else if (iR0 == 11) {
            strC0 = this.l;
            this.l = null;
        } else if (iR0 == 16) {
            strC0 = Long.toString(this.j);
        } else {
            if (iR0 != 17) {
                throw new JsonDataException("Expected a string but was " + Q() + " at path " + j());
            }
            long j = this.k;
            C5091h c5091h = this.h;
            c5091h.getClass();
            strC0 = c5091h.c0(j, Charsets.UTF_8);
        }
        this.i = 0;
        int[] iArr = this.d;
        int i = this.a - 1;
        iArr[i] = iArr[i] + 1;
        return strC0;
    }

    @Override // com.squareup.moshi.p
    public final o Q() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        switch (iR0) {
            case 1:
                return o.c;
            case 2:
                return o.d;
            case 3:
                return o.a;
            case 4:
                return o.b;
            case 5:
            case 6:
                return o.h;
            case 7:
                return o.i;
            case 8:
            case 9:
            case 10:
            case 11:
                return o.f;
            case 12:
            case 13:
            case 14:
            case 15:
                return o.e;
            case 16:
            case 17:
                return o.g;
            case 18:
                return o.j;
            default:
                throw new AssertionError();
        }
    }

    @Override // com.squareup.moshi.p
    public final p Y() {
        return new q(this);
    }

    @Override // com.squareup.moshi.p
    public final void a() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 3) {
            c0(1);
            this.d[this.a - 1] = 0;
            this.i = 0;
        } else {
            throw new JsonDataException("Expected BEGIN_ARRAY but was " + Q() + " at path " + j());
        }
    }

    @Override // com.squareup.moshi.p
    public final void a0() {
        if (l()) {
            this.l = B();
            this.i = 11;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.i = 0;
        this.b[0] = 8;
        this.a = 1;
        this.h.d();
        this.g.close();
    }

    @Override // com.squareup.moshi.p
    public final void d() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 1) {
            c0(3);
            this.i = 0;
        } else {
            throw new JsonDataException("Expected BEGIN_OBJECT but was " + Q() + " at path " + j());
        }
    }

    @Override // com.squareup.moshi.p
    public final void f() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 != 4) {
            throw new JsonDataException("Expected END_ARRAY but was " + Q() + " at path " + j());
        }
        int i = this.a;
        this.a = i - 1;
        int[] iArr = this.d;
        int i2 = i - 2;
        iArr[i2] = iArr[i2] + 1;
        this.i = 0;
    }

    @Override // com.squareup.moshi.p
    public final void i() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 != 2) {
            throw new JsonDataException("Expected END_OBJECT but was " + Q() + " at path " + j());
        }
        int i = this.a;
        int i2 = i - 1;
        this.a = i2;
        this.c[i2] = null;
        int[] iArr = this.d;
        int i3 = i - 2;
        iArr[i3] = iArr[i3] + 1;
        this.i = 0;
    }

    @Override // com.squareup.moshi.p
    public final int k0(com.airbnb.lottie.parser.moshi.c cVar) throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 < 12 || iR0 > 15) {
            return -1;
        }
        if (iR0 == 15) {
            return s0(this.l, cVar);
        }
        int iJ0 = this.g.j0(cVar.b);
        if (iJ0 != -1) {
            this.i = 0;
            this.c[this.a - 1] = cVar.a[iJ0];
            return iJ0;
        }
        String str = this.c[this.a - 1];
        String strB = B();
        int iS0 = s0(strB, cVar);
        if (iS0 == -1) {
            this.i = 15;
            this.l = strB;
            this.c[this.a - 1] = str;
        }
        return iS0;
    }

    @Override // com.squareup.moshi.p
    public final boolean l() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        return (iR0 == 2 || iR0 == 4 || iR0 == 18) ? false : true;
    }

    @Override // com.squareup.moshi.p
    public final int l0(com.airbnb.lottie.parser.moshi.c cVar) throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 < 8 || iR0 > 11) {
            return -1;
        }
        if (iR0 == 11) {
            return t0(this.l, cVar);
        }
        int iJ0 = this.g.j0(cVar.b);
        if (iJ0 != -1) {
            this.i = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return iJ0;
        }
        String strP = P();
        int iT0 = t0(strP, cVar);
        if (iT0 == -1) {
            this.i = 11;
            this.l = strP;
            this.d[this.a - 1] = r0[r1] - 1;
        }
        return iT0;
    }

    @Override // com.squareup.moshi.p
    public final void m0() throws EOFException, JsonEncodingException {
        if (this.f) {
            o oVarQ = Q();
            B();
            throw new JsonDataException("Cannot skip unexpected " + oVarQ + " at " + j());
        }
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 14) {
            long jX = this.g.x(p);
            C5091h c5091h = this.h;
            if (jX == -1) {
                jX = c5091h.b;
            }
            c5091h.skip(jX);
        } else if (iR0 == 13) {
            z0(o);
        } else if (iR0 == 12) {
            z0(n);
        } else if (iR0 != 15) {
            throw new JsonDataException("Expected a name but was " + Q() + " at path " + j());
        }
        this.i = 0;
        this.c[this.a - 1] = "null";
    }

    @Override // com.squareup.moshi.p
    public final void n0() throws EOFException, JsonEncodingException {
        if (this.f) {
            throw new JsonDataException("Cannot skip unexpected " + Q() + " at " + j());
        }
        int i = 0;
        do {
            int iR0 = this.i;
            if (iR0 == 0) {
                iR0 = r0();
            }
            if (iR0 == 3) {
                c0(1);
            } else if (iR0 == 1) {
                c0(3);
            } else {
                if (iR0 == 4) {
                    i--;
                    if (i < 0) {
                        throw new JsonDataException("Expected a value but was " + Q() + " at path " + j());
                    }
                    this.a--;
                } else if (iR0 == 2) {
                    i--;
                    if (i < 0) {
                        throw new JsonDataException("Expected a value but was " + Q() + " at path " + j());
                    }
                    this.a--;
                } else {
                    C5091h c5091h = this.h;
                    if (iR0 == 14 || iR0 == 10) {
                        long jX = this.g.x(p);
                        if (jX == -1) {
                            jX = c5091h.b;
                        }
                        c5091h.skip(jX);
                    } else if (iR0 == 9 || iR0 == 13) {
                        z0(o);
                    } else if (iR0 == 8 || iR0 == 12) {
                        z0(n);
                    } else if (iR0 == 17) {
                        c5091h.skip(this.k);
                    } else if (iR0 == 18) {
                        throw new JsonDataException("Expected a value but was " + Q() + " at path " + j());
                    }
                }
                this.i = 0;
            }
            i++;
            this.i = 0;
        } while (i != 0);
        int[] iArr = this.d;
        int i2 = this.a - 1;
        iArr[i2] = iArr[i2] + 1;
        this.c[i2] = "null";
    }

    @Override // com.squareup.moshi.p
    public final boolean p() throws EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 5) {
            this.i = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return true;
        }
        if (iR0 == 6) {
            this.i = 0;
            int[] iArr2 = this.d;
            int i2 = this.a - 1;
            iArr2[i2] = iArr2[i2] + 1;
            return false;
        }
        throw new JsonDataException("Expected a boolean but was " + Q() + " at path " + j());
    }

    @Override // com.squareup.moshi.p
    public final double q() throws NumberFormatException, EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 16) {
            this.i = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return this.j;
        }
        if (iR0 == 17) {
            long j = this.k;
            C5091h c5091h = this.h;
            c5091h.getClass();
            this.l = c5091h.c0(j, Charsets.UTF_8);
        } else if (iR0 == 9) {
            this.l = w0(o);
        } else if (iR0 == 8) {
            this.l = w0(n);
        } else if (iR0 == 10) {
            this.l = x0();
        } else if (iR0 != 11) {
            throw new JsonDataException("Expected a double but was " + Q() + " at path " + j());
        }
        this.i = 11;
        try {
            double d = Double.parseDouble(this.l);
            if (!this.e && (Double.isNaN(d) || Double.isInfinite(d))) {
                throw new JsonEncodingException("JSON forbids NaN and infinities: " + d + " at path " + j());
            }
            this.l = null;
            this.i = 0;
            int[] iArr2 = this.d;
            int i2 = this.a - 1;
            iArr2[i2] = iArr2[i2] + 1;
            return d;
        } catch (NumberFormatException unused) {
            throw new JsonDataException("Expected a double but was " + this.l + " at path " + j());
        }
    }

    public final void q0() throws JsonEncodingException {
        if (this.e) {
            return;
        }
        o0("Use JsonReader.setLenient(true) to accept malformed JSON");
        throw null;
    }

    @Override // com.squareup.moshi.p
    public final int r() throws NumberFormatException, EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 16) {
            long j = this.j;
            int i = (int) j;
            if (j == i) {
                this.i = 0;
                int[] iArr = this.d;
                int i2 = this.a - 1;
                iArr[i2] = iArr[i2] + 1;
                return i;
            }
            throw new JsonDataException("Expected an int but was " + this.j + " at path " + j());
        }
        if (iR0 == 17) {
            long j2 = this.k;
            C5091h c5091h = this.h;
            c5091h.getClass();
            this.l = c5091h.c0(j2, Charsets.UTF_8);
        } else if (iR0 == 9 || iR0 == 8) {
            String strW0 = iR0 == 9 ? w0(o) : w0(n);
            this.l = strW0;
            try {
                int i3 = Integer.parseInt(strW0);
                this.i = 0;
                int[] iArr2 = this.d;
                int i4 = this.a - 1;
                iArr2[i4] = iArr2[i4] + 1;
                return i3;
            } catch (NumberFormatException unused) {
            }
        } else if (iR0 != 11) {
            throw new JsonDataException("Expected an int but was " + Q() + " at path " + j());
        }
        this.i = 11;
        try {
            double d = Double.parseDouble(this.l);
            int i5 = (int) d;
            if (i5 != d) {
                throw new JsonDataException("Expected an int but was " + this.l + " at path " + j());
            }
            this.l = null;
            this.i = 0;
            int[] iArr3 = this.d;
            int i6 = this.a - 1;
            iArr3[i6] = iArr3[i6] + 1;
            return i5;
        } catch (NumberFormatException unused2) {
            throw new JsonDataException("Expected an int but was " + this.l + " at path " + j());
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:103:0x016b, code lost:
    
        r3 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x01da, code lost:
    
        if (u0(r7) != false) goto L126;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x01dd, code lost:
    
        if (r2 != 2) goto L161;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x01df, code lost:
    
        if (r5 == 0) goto L153;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x01e5, code lost:
    
        if (r18 != Long.MIN_VALUE) goto L154;
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x01e7, code lost:
    
        if (r6 == 0) goto L153;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x01ea, code lost:
    
        r3 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x01ee, code lost:
    
        if (r18 != r16) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x01f0, code lost:
    
        if (r6 != 0) goto L153;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x01f2, code lost:
    
        if (r6 == 0) goto L159;
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x01f4, code lost:
    
        r8 = r18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x01f7, code lost:
    
        r8 = -r18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x01fa, code lost:
    
        r23.j = r8;
        r11.skip(r4);
        r10 = 16;
        r23.i = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x0205, code lost:
    
        if (r2 == r3) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x0208, code lost:
    
        if (r2 == 4) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x020b, code lost:
    
        if (r2 != 7) goto L126;
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x020d, code lost:
    
        r23.k = r4;
        r10 = 17;
        r23.i = 17;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x015a  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x023b A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:186:0x023c  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x0290  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00ca  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0159 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int r0() throws java.io.EOFException, com.squareup.moshi.JsonEncodingException {
        /*
            Method dump skipped, instructions count: 779
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.squareup.moshi.q.r0():int");
    }

    public final int s0(String str, com.airbnb.lottie.parser.moshi.c cVar) {
        int length = cVar.a.length;
        for (int i = 0; i < length; i++) {
            if (str.equals(cVar.a[i])) {
                this.i = 0;
                this.c[this.a - 1] = str;
                return i;
            }
        }
        return -1;
    }

    public final int t0(String str, com.airbnb.lottie.parser.moshi.c cVar) {
        int length = cVar.a.length;
        for (int i = 0; i < length; i++) {
            if (str.equals(cVar.a[i])) {
                this.i = 0;
                int[] iArr = this.d;
                int i2 = this.a - 1;
                iArr[i2] = iArr[i2] + 1;
                return i;
            }
        }
        return -1;
    }

    public final String toString() {
        return "JsonReader(" + this.g + ")";
    }

    public final boolean u0(int i) throws JsonEncodingException {
        if (i == 9 || i == 10 || i == 12 || i == 13 || i == 32) {
            return false;
        }
        if (i != 35) {
            if (i == 44) {
                return false;
            }
            if (i != 47 && i != 61) {
                if (i == 123 || i == 125 || i == 58) {
                    return false;
                }
                if (i != 59) {
                    switch (i) {
                        case 91:
                        case 93:
                            return false;
                        case 92:
                            break;
                        default:
                            return true;
                    }
                }
            }
        }
        q0();
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x0026, code lost:
    
        r1.skip(r3);
        r2 = com.squareup.moshi.q.q;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0031, code lost:
    
        if (r6 != 47) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0039, code lost:
    
        if (r5.e(2) != false) goto L20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x003d, code lost:
    
        q0();
        r10 = r1.p(1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0046, code lost:
    
        if (r10 == 42) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0048, code lost:
    
        if (r10 == 47) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004b, code lost:
    
        r1.readByte();
        r1.readByte();
        r5 = r5.x(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0057, code lost:
    
        if (r5 == (-1)) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0059, code lost:
    
        r5 = r5 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x005b, code lost:
    
        r5 = r1.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x005d, code lost:
    
        r1.skip(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0061, code lost:
    
        r1.readByte();
        r1.readByte();
        r5 = r5.t(com.squareup.moshi.q.r);
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x006f, code lost:
    
        if (r5 == (-1)) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0071, code lost:
    
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0073, code lost:
    
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0074, code lost:
    
        if (r3 == false) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0076, code lost:
    
        r5 = r5 + r2.a.length;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007c, code lost:
    
        r5 = r1.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x007e, code lost:
    
        r1.skip(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0081, code lost:
    
        if (r3 == false) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0085, code lost:
    
        o0("Unterminated comment");
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x008b, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x008e, code lost:
    
        if (r6 != 35) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0090, code lost:
    
        q0();
        r5 = r5.x(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0099, code lost:
    
        if (r5 == (-1)) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x009b, code lost:
    
        r5 = r5 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x009d, code lost:
    
        r5 = r1.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x009f, code lost:
    
        r1.skip(r5);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int v0(boolean r13) throws java.io.EOFException, com.squareup.moshi.JsonEncodingException {
        /*
            r12 = this;
            r0 = 0
        L1:
            r1 = r0
        L2:
            int r2 = r1 + 1
            long r3 = (long) r2
            okio.j r5 = r12.g
            boolean r3 = r5.e(r3)
            if (r3 == 0) goto La8
            long r3 = (long) r1
            okio.h r1 = r12.h
            byte r6 = r1.p(r3)
            r7 = 10
            if (r6 == r7) goto La5
            r7 = 32
            if (r6 == r7) goto La5
            r7 = 13
            if (r6 == r7) goto La5
            r7 = 9
            if (r6 != r7) goto L26
            goto La5
        L26:
            r1.skip(r3)
            okio.k r2 = com.squareup.moshi.q.q
            r3 = -1
            r7 = 1
            r9 = 47
            if (r6 != r9) goto L8c
            r10 = 2
            boolean r10 = r5.e(r10)
            if (r10 != 0) goto L3d
            goto La4
        L3d:
            r12.q0()
            byte r10 = r1.p(r7)
            r11 = 42
            if (r10 == r11) goto L61
            if (r10 == r9) goto L4b
            goto La4
        L4b:
            r1.readByte()
            r1.readByte()
            long r5 = r5.x(r2)
            int r2 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r2 == 0) goto L5b
            long r5 = r5 + r7
            goto L5d
        L5b:
            long r5 = r1.b
        L5d:
            r1.skip(r5)
            goto L1
        L61:
            r1.readByte()
            r1.readByte()
            okio.k r2 = com.squareup.moshi.q.r
            long r5 = r5.t(r2)
            int r3 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r3 == 0) goto L73
            r3 = 1
            goto L74
        L73:
            r3 = r0
        L74:
            if (r3 == 0) goto L7c
            byte[] r2 = r2.a
            int r2 = r2.length
            long r7 = (long) r2
            long r5 = r5 + r7
            goto L7e
        L7c:
            long r5 = r1.b
        L7e:
            r1.skip(r5)
            if (r3 == 0) goto L85
            goto L1
        L85:
            java.lang.String r13 = "Unterminated comment"
            r12.o0(r13)
            r13 = 0
            throw r13
        L8c:
            r9 = 35
            if (r6 != r9) goto La4
            r12.q0()
            long r5 = r5.x(r2)
            int r2 = (r5 > r3 ? 1 : (r5 == r3 ? 0 : -1))
            if (r2 == 0) goto L9d
            long r5 = r5 + r7
            goto L9f
        L9d:
            long r5 = r1.b
        L9f:
            r1.skip(r5)
            goto L1
        La4:
            return r6
        La5:
            r1 = r2
            goto L2
        La8:
            if (r13 != 0) goto Lac
            r13 = -1
            return r13
        Lac:
            java.io.EOFException r13 = new java.io.EOFException
            java.lang.String r0 = "End of input"
            r13.<init>(r0)
            throw r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.squareup.moshi.q.v0(boolean):int");
    }

    public final String w0(okio.k kVar) throws EOFException, JsonEncodingException {
        StringBuilder sb = null;
        while (true) {
            long jX = this.g.x(kVar);
            if (jX == -1) {
                o0("Unterminated string");
                throw null;
            }
            C5091h c5091h = this.h;
            if (c5091h.p(jX) != 92) {
                if (sb == null) {
                    String strC0 = c5091h.c0(jX, Charsets.UTF_8);
                    c5091h.readByte();
                    return strC0;
                }
                sb.append(c5091h.c0(jX, Charsets.UTF_8));
                c5091h.readByte();
                return sb.toString();
            }
            if (sb == null) {
                sb = new StringBuilder();
            }
            sb.append(c5091h.c0(jX, Charsets.UTF_8));
            c5091h.readByte();
            sb.append(y0());
        }
    }

    public final String x0() {
        long jX = this.g.x(p);
        C5091h c5091h = this.h;
        if (jX == -1) {
            return c5091h.U();
        }
        c5091h.getClass();
        return c5091h.c0(jX, Charsets.UTF_8);
    }

    @Override // com.squareup.moshi.p
    public final long y() throws NumberFormatException, EOFException, JsonEncodingException {
        int iR0 = this.i;
        if (iR0 == 0) {
            iR0 = r0();
        }
        if (iR0 == 16) {
            this.i = 0;
            int[] iArr = this.d;
            int i = this.a - 1;
            iArr[i] = iArr[i] + 1;
            return this.j;
        }
        if (iR0 == 17) {
            long j = this.k;
            C5091h c5091h = this.h;
            c5091h.getClass();
            this.l = c5091h.c0(j, Charsets.UTF_8);
        } else if (iR0 == 9 || iR0 == 8) {
            String strW0 = iR0 == 9 ? w0(o) : w0(n);
            this.l = strW0;
            try {
                long j2 = Long.parseLong(strW0);
                this.i = 0;
                int[] iArr2 = this.d;
                int i2 = this.a - 1;
                iArr2[i2] = iArr2[i2] + 1;
                return j2;
            } catch (NumberFormatException unused) {
            }
        } else if (iR0 != 11) {
            throw new JsonDataException("Expected a long but was " + Q() + " at path " + j());
        }
        this.i = 11;
        try {
            long jLongValueExact = new BigDecimal(this.l).longValueExact();
            this.l = null;
            this.i = 0;
            int[] iArr3 = this.d;
            int i3 = this.a - 1;
            iArr3[i3] = iArr3[i3] + 1;
            return jLongValueExact;
        } catch (ArithmeticException | NumberFormatException unused2) {
            throw new JsonDataException("Expected a long but was " + this.l + " at path " + j());
        }
    }

    public final char y0() throws EOFException, JsonEncodingException {
        int i;
        InterfaceC5093j interfaceC5093j = this.g;
        if (!interfaceC5093j.e(1L)) {
            o0("Unterminated escape sequence");
            throw null;
        }
        C5091h c5091h = this.h;
        byte b = c5091h.readByte();
        if (b == 10 || b == 34 || b == 39 || b == 47 || b == 92) {
            return (char) b;
        }
        if (b == 98) {
            return '\b';
        }
        if (b == 102) {
            return '\f';
        }
        if (b == 110) {
            return '\n';
        }
        if (b == 114) {
            return '\r';
        }
        if (b == 116) {
            return '\t';
        }
        if (b != 117) {
            if (this.e) {
                return (char) b;
            }
            o0("Invalid escape sequence: \\" + ((char) b));
            throw null;
        }
        if (!interfaceC5093j.e(4L)) {
            throw new EOFException("Unterminated escape sequence at path " + j());
        }
        char c = 0;
        for (int i2 = 0; i2 < 4; i2++) {
            byte bP = c5091h.p(i2);
            char c2 = (char) (c << 4);
            if (bP >= 48 && bP <= 57) {
                i = bP - 48;
            } else if (bP >= 97 && bP <= 102) {
                i = bP - 87;
            } else {
                if (bP < 65 || bP > 70) {
                    o0("\\u".concat(c5091h.c0(4L, Charsets.UTF_8)));
                    throw null;
                }
                i = bP - 55;
            }
            c = (char) (i + c2);
        }
        c5091h.skip(4L);
        return c;
    }

    public final void z0(okio.k kVar) throws EOFException, JsonEncodingException {
        while (true) {
            long jX = this.g.x(kVar);
            if (jX == -1) {
                o0("Unterminated string");
                throw null;
            }
            C5091h c5091h = this.h;
            if (c5091h.p(jX) != 92) {
                c5091h.skip(jX + 1);
                return;
            } else {
                c5091h.skip(jX + 1);
                y0();
            }
        }
    }

    public q(q qVar) {
        super(qVar);
        this.i = 0;
        okio.A aPeek = qVar.g.peek();
        this.g = aPeek;
        this.h = aPeek.b;
        this.i = qVar.i;
        this.j = qVar.j;
        this.k = qVar.k;
        this.l = qVar.l;
        try {
            aPeek.k(qVar.h.b);
        } catch (IOException unused) {
            throw new AssertionError();
        }
    }
}
