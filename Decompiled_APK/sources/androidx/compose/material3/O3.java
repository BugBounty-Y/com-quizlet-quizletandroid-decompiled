package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;

/* loaded from: classes.dex */
public final class O3 {
    public final kotlinx.coroutines.sync.c a = kotlinx.coroutines.sync.d.a();
    public final InterfaceC0773a0 b = C0776c.z(null);

    public static Object b(O3 o3, String str, kotlin.coroutines.jvm.internal.i iVar) {
        o3.getClass();
        return o3.a(new M3(str, 1), iVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r8v0, types: [androidx.compose.material3.V3] */
    /* JADX WARN: Type inference failed for: r8v11, types: [kotlinx.coroutines.sync.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(androidx.compose.material3.V3 r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof androidx.compose.material3.N3
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.material3.N3 r0 = (androidx.compose.material3.N3) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.compose.material3.N3 r0 = new androidx.compose.material3.N3
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L47
            if (r2 == r4) goto L3b
            if (r2 != r3) goto L33
            kotlinx.coroutines.sync.a r8 = r0.l
            androidx.compose.material3.O3 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L30
            goto L94
        L30:
            r9 = move-exception
            goto La3
        L33:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L3b:
            kotlinx.coroutines.sync.a r8 = r0.l
            androidx.compose.material3.V3 r2 = r0.k
            androidx.compose.material3.O3 r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r9 = r8
            r8 = r2
            goto L5c
        L47:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r7
            r0.k = r8
            kotlinx.coroutines.sync.c r9 = r7.a
            r0.l = r9
            r0.o = r4
            java.lang.Object r2 = r9.d(r0)
            if (r2 != r1) goto L5b
            goto L8f
        L5b:
            r6 = r7
        L5c:
            r0.j = r6     // Catch: java.lang.Throwable -> La1
            r0.k = r8     // Catch: java.lang.Throwable -> La1
            r0.l = r9     // Catch: java.lang.Throwable -> La1
            r0.o = r3     // Catch: java.lang.Throwable -> La1
            kotlinx.coroutines.l r2 = new kotlinx.coroutines.l     // Catch: java.lang.Throwable -> La1
            kotlin.coroutines.h r3 = kotlin.coroutines.intrinsics.h.b(r0)     // Catch: java.lang.Throwable -> La1
            r2.<init>(r4, r3)     // Catch: java.lang.Throwable -> La1
            r2.r()     // Catch: java.lang.Throwable -> La1
            androidx.compose.material3.L3 r3 = new androidx.compose.material3.L3     // Catch: java.lang.Throwable -> La1
            r3.<init>(r8, r2)     // Catch: java.lang.Throwable -> La1
            androidx.compose.runtime.a0 r8 = r6.b     // Catch: java.lang.Throwable -> La1
            androidx.compose.runtime.L0 r8 = (androidx.compose.runtime.L0) r8     // Catch: java.lang.Throwable -> La1
            r8.setValue(r3)     // Catch: java.lang.Throwable -> La1
            java.lang.Object r8 = r2.q()     // Catch: java.lang.Throwable -> La1
            if (r8 != r1) goto L8d
            java.lang.String r2 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)     // Catch: java.lang.Throwable -> La1
            goto L8d
        L88:
            r0 = r9
            r9 = r8
            r8 = r0
            r0 = r6
            goto La3
        L8d:
            if (r8 != r1) goto L90
        L8f:
            return r1
        L90:
            r0 = r9
            r9 = r8
            r8 = r0
            r0 = r6
        L94:
            androidx.compose.runtime.a0 r0 = r0.b     // Catch: java.lang.Throwable -> Lab
            androidx.compose.runtime.L0 r0 = (androidx.compose.runtime.L0) r0     // Catch: java.lang.Throwable -> Lab
            r0.setValue(r5)     // Catch: java.lang.Throwable -> Lab
            kotlinx.coroutines.sync.c r8 = (kotlinx.coroutines.sync.c) r8
            r8.f(r5)
            return r9
        La1:
            r8 = move-exception
            goto L88
        La3:
            androidx.compose.runtime.a0 r0 = r0.b     // Catch: java.lang.Throwable -> Lab
            androidx.compose.runtime.L0 r0 = (androidx.compose.runtime.L0) r0     // Catch: java.lang.Throwable -> Lab
            r0.setValue(r5)     // Catch: java.lang.Throwable -> Lab
            throw r9     // Catch: java.lang.Throwable -> Lab
        Lab:
            r9 = move-exception
            kotlinx.coroutines.sync.c r8 = (kotlinx.coroutines.sync.c) r8
            r8.f(r5)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.O3.a(androidx.compose.material3.V3, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
