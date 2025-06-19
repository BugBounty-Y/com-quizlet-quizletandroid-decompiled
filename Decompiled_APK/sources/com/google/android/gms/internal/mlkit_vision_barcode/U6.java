package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.datastore.preferences.protobuf.C1100g;

/* loaded from: classes2.dex */
public abstract class U6 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r8v0, types: [io.ktor.client.engine.d, io.ktor.client.engine.okhttp.f] */
    /* JADX WARN: Type inference failed for: r8v1, types: [io.ktor.client.engine.d, kotlinx.coroutines.C] */
    /* JADX WARN: Type inference failed for: r8v4, types: [io.ktor.client.engine.d] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(io.ktor.client.engine.okhttp.f r8, io.ktor.client.request.d r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            boolean r0 = r10 instanceof io.ktor.client.engine.a
            if (r0 == 0) goto L13
            r0 = r10
            io.ktor.client.engine.a r0 = (io.ktor.client.engine.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            io.ktor.client.engine.a r0 = new io.ktor.client.engine.a
            r0.<init>(r10)
        L18:
            java.lang.Object r10 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            r4 = 2
            if (r2 == 0) goto L3a
            if (r2 == r3) goto L32
            if (r2 != r4) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r10)
            return r10
        L2a:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L32:
            io.ktor.client.request.d r9 = r0.k
            io.ktor.client.engine.d r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L7d
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.A0 r10 = r9.e
            r0.j = r8
            r0.k = r9
            r0.m = r3
            kotlinx.coroutines.B r2 = io.ktor.client.engine.i.a
            kotlinx.coroutines.k0 r2 = new kotlinx.coroutines.k0
            r2.<init>(r10)
            kotlin.coroutines.CoroutineContext r10 = r8.g
            kotlin.coroutines.CoroutineContext r10 = r10.plus(r2)
            kotlinx.coroutines.B r5 = io.ktor.client.engine.i.a
            kotlin.coroutines.CoroutineContext r10 = r10.plus(r5)
            kotlin.coroutines.CoroutineContext r5 = r0.getContext()
            kotlinx.coroutines.i0 r6 = kotlinx.coroutines.C5023i0.a
            kotlin.coroutines.CoroutineContext$Element r5 = r5.get(r6)
            kotlinx.coroutines.j0 r5 = (kotlinx.coroutines.InterfaceC5025j0) r5
            if (r5 != 0) goto L67
            goto L7a
        L67:
            io.ktor.client.engine.k r6 = new io.ktor.client.engine.k
            r7 = 0
            r6.<init>(r2, r7)
            kotlinx.coroutines.Q r3 = r5.q(r3, r3, r6)
            androidx.compose.ui.input.pointer.u r5 = new androidx.compose.ui.input.pointer.u
            r6 = 4
            r5.<init>(r3, r6)
            r2.Q(r5)
        L7a:
            if (r10 != r1) goto L7d
            goto L9e
        L7d:
            kotlin.coroutines.CoroutineContext r10 = (kotlin.coroutines.CoroutineContext) r10
            io.ktor.client.engine.j r2 = new io.ktor.client.engine.j
            r2.<init>(r10)
            kotlin.coroutines.CoroutineContext r10 = r10.plus(r2)
            io.ktor.client.engine.b r2 = new io.ktor.client.engine.b
            r3 = 0
            r2.<init>(r8, r9, r3)
            kotlinx.coroutines.I r8 = kotlinx.coroutines.E.f(r8, r10, r2, r4)
            r0.j = r3
            r0.k = r3
            r0.m = r4
            java.lang.Object r8 = r8.w(r0)
            if (r8 != r1) goto L9f
        L9e:
            return r1
        L9f:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.U6.a(io.ktor.client.engine.okhttp.f, io.ktor.client.request.d, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static String b(C1100g c1100g) {
        StringBuilder sb = new StringBuilder(c1100g.size());
        for (int i = 0; i < c1100g.size(); i++) {
            byte bA = c1100g.a(i);
            if (bA == 34) {
                sb.append("\\\"");
            } else if (bA == 39) {
                sb.append("\\'");
            } else if (bA != 92) {
                switch (bA) {
                    case 7:
                        sb.append("\\a");
                        break;
                    case 8:
                        sb.append("\\b");
                        break;
                    case 9:
                        sb.append("\\t");
                        break;
                    case 10:
                        sb.append("\\n");
                        break;
                    case 11:
                        sb.append("\\v");
                        break;
                    case 12:
                        sb.append("\\f");
                        break;
                    case 13:
                        sb.append("\\r");
                        break;
                    default:
                        if (bA < 32 || bA > 126) {
                            sb.append('\\');
                            sb.append((char) (((bA >>> 6) & 3) + 48));
                            sb.append((char) (((bA >>> 3) & 7) + 48));
                            sb.append((char) ((bA & 7) + 48));
                            break;
                        } else {
                            sb.append((char) bA);
                            break;
                        }
                }
            } else {
                sb.append("\\\\");
            }
        }
        return sb.toString();
    }
}
