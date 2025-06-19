package com.squareup.moshi;

import okio.C5091h;
import okio.I;
import okio.InterfaceC5093j;

/* loaded from: classes3.dex */
public final class v implements okio.G {
    public static final okio.k h;
    public static final okio.k i;
    public static final okio.k j;
    public static final okio.k k;
    public static final okio.k l;
    public static final okio.k m;
    public final InterfaceC5093j a;
    public final C5091h b;
    public final C5091h c;
    public okio.k d;
    public int e;
    public long f = 0;
    public boolean g = false;

    static {
        okio.k kVar = okio.k.d;
        h = com.quizlet.quizletandroid.ui.common.images.capture.b.i("[]{}\"'/#");
        i = com.quizlet.quizletandroid.ui.common.images.capture.b.i("'\\");
        j = com.quizlet.quizletandroid.ui.common.images.capture.b.i("\"\\");
        k = com.quizlet.quizletandroid.ui.common.images.capture.b.i("\r\n");
        l = com.quizlet.quizletandroid.ui.common.images.capture.b.i("*");
        m = okio.k.d;
    }

    public v(InterfaceC5093j interfaceC5093j, C5091h c5091h, okio.k kVar, int i2) {
        this.a = interfaceC5093j;
        this.b = interfaceC5093j.c();
        this.c = c5091h;
        this.d = kVar;
        this.e = i2;
    }

    public final void a(long j2) {
        while (true) {
            long j3 = this.f;
            if (j3 >= j2) {
                return;
            }
            okio.k kVar = this.d;
            okio.k kVar2 = m;
            if (kVar == kVar2) {
                return;
            }
            C5091h c5091h = this.b;
            long j4 = c5091h.b;
            InterfaceC5093j interfaceC5093j = this.a;
            if (j3 == j4) {
                if (j3 > 0) {
                    return;
                } else {
                    interfaceC5093j.k(1L);
                }
            }
            long jY = c5091h.y(this.f, this.d);
            if (jY == -1) {
                this.f = c5091h.b;
            } else {
                byte bP = c5091h.p(jY);
                okio.k kVar3 = this.d;
                okio.k kVar4 = h;
                okio.k kVar5 = j;
                okio.k kVar6 = i;
                okio.k kVar7 = l;
                okio.k kVar8 = k;
                if (kVar3 == kVar4) {
                    if (bP == 34) {
                        this.d = kVar5;
                        this.f = jY + 1;
                    } else if (bP == 35) {
                        this.d = kVar8;
                        this.f = jY + 1;
                    } else if (bP == 39) {
                        this.d = kVar6;
                        this.f = jY + 1;
                    } else if (bP != 47) {
                        if (bP != 91) {
                            if (bP != 93) {
                                if (bP != 123) {
                                    if (bP != 125) {
                                    }
                                }
                            }
                            int i2 = this.e - 1;
                            this.e = i2;
                            if (i2 == 0) {
                                this.d = kVar2;
                            }
                            this.f = jY + 1;
                        }
                        this.e++;
                        this.f = jY + 1;
                    } else {
                        long j5 = jY + 2;
                        interfaceC5093j.k(j5);
                        long j6 = jY + 1;
                        byte bP2 = c5091h.p(j6);
                        if (bP2 == 47) {
                            this.d = kVar8;
                            this.f = j5;
                        } else if (bP2 == 42) {
                            this.d = kVar7;
                            this.f = j5;
                        } else {
                            this.f = j6;
                        }
                    }
                } else if (kVar3 == kVar6 || kVar3 == kVar5) {
                    if (bP == 92) {
                        long j7 = jY + 2;
                        interfaceC5093j.k(j7);
                        this.f = j7;
                    } else {
                        if (this.e > 0) {
                            kVar2 = kVar4;
                        }
                        this.d = kVar2;
                        this.f = jY + 1;
                    }
                } else if (kVar3 == kVar7) {
                    long j8 = jY + 2;
                    interfaceC5093j.k(j8);
                    long j9 = jY + 1;
                    if (c5091h.p(j9) == 47) {
                        this.f = j8;
                        this.d = kVar4;
                    } else {
                        this.f = j9;
                    }
                } else {
                    if (kVar3 != kVar8) {
                        throw new AssertionError();
                    }
                    this.f = jY + 1;
                    this.d = kVar4;
                }
            }
        }
    }

    @Override // okio.G
    public final long b0(C5091h c5091h, long j2) {
        if (this.g) {
            throw new IllegalStateException("closed");
        }
        if (j2 == 0) {
            return 0L;
        }
        C5091h c5091h2 = this.c;
        boolean zU = c5091h2.u();
        C5091h c5091h3 = this.b;
        if (!zU) {
            long jB0 = c5091h2.b0(c5091h, j2);
            long j3 = j2 - jB0;
            if (!c5091h3.u()) {
                long jB02 = b0(c5091h, j3);
                if (jB02 != -1) {
                    return jB02 + jB0;
                }
            }
            return jB0;
        }
        a(j2);
        long j4 = this.f;
        if (j4 == 0) {
            if (this.d == m) {
                return -1L;
            }
            throw new AssertionError();
        }
        long jMin = Math.min(j2, j4);
        c5091h.L(c5091h3, jMin);
        this.f -= jMin;
        return jMin;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.g = true;
    }

    @Override // okio.G
    public final I h() {
        return this.a.h();
    }
}
