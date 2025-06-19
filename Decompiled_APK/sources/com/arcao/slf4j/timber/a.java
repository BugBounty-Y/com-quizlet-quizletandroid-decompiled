package com.arcao.slf4j.timber;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.jvm.internal.Intrinsics;
import org.slf4j.helpers.f;
import timber.log.c;

/* loaded from: classes.dex */
public final class a extends f {
    @Override // org.slf4j.b
    public final boolean a() {
        return true;
    }

    @Override // org.slf4j.b
    public final boolean b() {
        return true;
    }

    @Override // org.slf4j.b
    public final void c(String str, Throwable th) {
        q(5, str, th);
    }

    @Override // org.slf4j.b
    public final boolean d() {
        return true;
    }

    @Override // org.slf4j.b
    public final boolean e() {
        return true;
    }

    @Override // org.slf4j.b
    public final void error(String str) {
        q(5, str, null);
    }

    @Override // org.slf4j.b
    public final void f(String str) {
        q(2, str, null);
    }

    @Override // org.slf4j.b
    public final boolean g() {
        return true;
    }

    @Override // org.slf4j.b
    public final void h(String str, Throwable th) {
        q(3, str, th);
    }

    @Override // org.slf4j.b
    public final void j(String str, Throwable th) {
        q(4, str, th);
    }

    @Override // org.slf4j.b
    public final void k(String str, Throwable th) {
        q(1, str, th);
    }

    @Override // org.slf4j.b
    public final void l(String str, Throwable th) {
        q(2, str, th);
    }

    @Override // org.slf4j.b
    public final void m(String str) {
        q(3, str, null);
    }

    @Override // org.slf4j.b
    public final void n(String str) {
        q(1, str, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x006e  */
    @Override // org.slf4j.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p(java.lang.String r10, java.lang.String r11) {
        /*
            r9 = this;
            r0 = 1
            java.lang.Object[] r1 = new java.lang.Object[r0]
            r2 = 0
            r1[r2] = r11
            r11 = 0
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            int r4 = r10.length()
            int r4 = r4 + 50
            r3.<init>(r4)
            r4 = r2
        L13:
            int r5 = r1.length
            if (r2 >= r5) goto L7e
            java.lang.String r5 = "{}"
            int r5 = r10.indexOf(r5, r4)
            r6 = -1
            if (r5 != r6) goto L38
            if (r4 != 0) goto L27
            io.ktor.client.plugins.api.d r0 = new io.ktor.client.plugins.api.d
            r0.<init>(r11, r10, r1)
            goto L8e
        L27:
            int r0 = r10.length()
            r3.append(r10, r4, r0)
            io.ktor.client.plugins.api.d r0 = new io.ktor.client.plugins.api.d
            java.lang.String r10 = r3.toString()
            r0.<init>(r11, r10, r1)
            goto L8e
        L38:
            if (r5 != 0) goto L3b
            goto L6e
        L3b:
            int r6 = r5 + (-1)
            char r7 = r10.charAt(r6)
            r8 = 92
            if (r7 != r8) goto L6e
            r7 = 2
            if (r5 < r7) goto L61
            int r7 = r5 + (-2)
            char r7 = r10.charAt(r7)
            if (r7 != r8) goto L61
            r3.append(r10, r4, r6)
            r4 = r1[r2]
            java.util.HashMap r6 = new java.util.HashMap
            r6.<init>()
            com.google.android.gms.internal.mlkit_vision_camera.B2.b(r3, r4, r6)
        L5d:
            int r5 = r5 + 2
        L5f:
            r4 = r5
            goto L7c
        L61:
            int r2 = r2 + (-1)
            r3.append(r10, r4, r6)
            r4 = 123(0x7b, float:1.72E-43)
            r3.append(r4)
            int r5 = r5 + 1
            goto L5f
        L6e:
            r3.append(r10, r4, r5)
            r4 = r1[r2]
            java.util.HashMap r6 = new java.util.HashMap
            r6.<init>()
            com.google.android.gms.internal.mlkit_vision_camera.B2.b(r3, r4, r6)
            goto L5d
        L7c:
            int r2 = r2 + r0
            goto L13
        L7e:
            int r0 = r10.length()
            r3.append(r10, r4, r0)
            io.ktor.client.plugins.api.d r0 = new io.ktor.client.plugins.api.d
            java.lang.String r10 = r3.toString()
            r0.<init>(r11, r10, r1)
        L8e:
            java.lang.Object r10 = r0.b
            java.lang.String r10 = (java.lang.String) r10
            java.lang.Object r11 = r0.c
            java.lang.Throwable r11 = (java.lang.Throwable) r11
            r0 = 3
            r9.q(r0, r10, r11)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.arcao.slf4j.timber.a.p(java.lang.String, java.lang.String):void");
    }

    public final void q(int i, String str, Throwable th) {
        String tag = this.a;
        timber.log.a aVar = c.a;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(tag, "tag");
        timber.log.b[] bVarArr = c.c;
        int length = bVarArr.length;
        int i2 = 0;
        while (i2 < length) {
            timber.log.b bVar = bVarArr[i2];
            i2++;
            bVar.a.set(tag);
        }
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            if (th != null) {
                aVar.n(th, str, new Object[0]);
                return;
            } else {
                aVar.m(str, new Object[0]);
                return;
            }
        }
        if (iK == 1) {
            if (th != null) {
                aVar.c(th, str, new Object[0]);
                return;
            } else {
                aVar.a(str, new Object[0]);
                return;
            }
        }
        if (iK == 3) {
            if (th != null) {
                aVar.q(th, str, new Object[0]);
                return;
            } else {
                aVar.o(str, new Object[0]);
                return;
            }
        }
        if (iK != 4) {
            if (th != null) {
                aVar.i(th, str, new Object[0]);
                return;
            } else {
                aVar.g(str, new Object[0]);
                return;
            }
        }
        if (th != null) {
            aVar.f(th, str, new Object[0]);
        } else {
            aVar.d(str, new Object[0]);
        }
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(a.class.getName());
        sb.append("(");
        return android.support.v4.media.session.a.t(sb, this.a, ")");
    }

    @Override // org.slf4j.b
    public final void warn(String str) {
        q(4, str, null);
    }
}
