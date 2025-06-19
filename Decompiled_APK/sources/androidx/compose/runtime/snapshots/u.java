package androidx.compose.runtime.snapshots;

import androidx.collection.I;
import androidx.collection.J;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0812o;
import com.google.android.gms.internal.mlkit_vision_barcode.F4;
import java.util.HashMap;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class u {
    public final Function1 a;
    public Object b;
    public androidx.collection.C c;
    public int j;
    public int d = -1;
    public final I e = F4.c();
    public final I f = new I();
    public final J g = new J();
    public final androidx.compose.runtime.collection.b h = new androidx.compose.runtime.collection.b(new androidx.compose.runtime.E[16]);
    public final C0812o i = new C0812o(this, 1);
    public final I k = F4.c();
    public final HashMap l = new HashMap();

    public u(Function1 function1) {
        this.a = function1;
    }

    public final void a(Object obj, C0775b0 c0775b0, Function0 function0) {
        boolean z;
        int i;
        int i2;
        Object obj2 = this.b;
        androidx.collection.C c = this.c;
        int i3 = this.d;
        this.b = obj;
        this.c = (androidx.collection.C) this.f.f(obj);
        if (this.d == -1) {
            this.d = Long.hashCode(m.k().g());
        }
        C0812o c0812o = this.i;
        androidx.compose.runtime.collection.b bVarO = C0776c.o();
        boolean z2 = true;
        try {
            bVarO.b(c0812o);
            r.f(function0, c0775b0);
            bVarO.o(bVarO.c - 1);
            Object obj3 = this.b;
            Intrinsics.d(obj3);
            int i4 = this.d;
            androidx.collection.C c2 = this.c;
            if (c2 != null) {
                long[] jArr = c2.a;
                int length = jArr.length - 2;
                if (length >= 0) {
                    int i5 = 0;
                    while (true) {
                        long j = jArr[i5];
                        if ((((~j) << 7) & j & (-9187201950435737472L)) != -9187201950435737472L) {
                            int i6 = 8;
                            int i7 = 8 - ((~(i5 - length)) >>> 31);
                            z = z2;
                            int i8 = 0;
                            while (i8 < i7) {
                                if ((j & 255) < 128) {
                                    int i9 = (i5 << 3) + i8;
                                    i2 = i6;
                                    Object obj4 = c2.b[i9];
                                    i = i8;
                                    boolean z3 = c2.c[i9] != i4 ? z : false;
                                    if (z3) {
                                        d(obj3, obj4);
                                    }
                                    if (z3) {
                                        c2.f(i9);
                                    }
                                } else {
                                    i = i8;
                                    i2 = i6;
                                }
                                j >>= i2;
                                i8 = i + 1;
                                i6 = i2;
                            }
                            if (i7 != i6) {
                                break;
                            }
                        } else {
                            z = z2;
                        }
                        if (i5 == length) {
                            break;
                        }
                        i5++;
                        z2 = z;
                    }
                }
            }
            this.b = obj2;
            this.c = c;
            this.d = i3;
        } catch (Throwable th) {
            bVarO.o(bVarO.c - 1);
            throw th;
        }
    }

    /*  JADX ERROR: Type inference failed
        jadx.core.utils.exceptions.JadxOverflowException: Type inference error: updates count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        	at jadx.core.dex.visitors.typeinference.TypeInferenceVisitor.visit(TypeInferenceVisitor.java:77)
        */
    public final boolean b(java.util.Set r47) {
        /*
            Method dump skipped, instructions count: 1548
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.u.b(java.util.Set):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x008b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(java.lang.Object r21, int r22, java.lang.Object r23, androidx.collection.C r24) {
        /*
            r20 = this;
            r0 = r20
            r1 = r21
            r2 = r22
            r3 = r24
            int r4 = r0.j
            if (r4 <= 0) goto Le
            goto La4
        Le:
            int r4 = r3.b(r1)
            if (r4 >= 0) goto L17
            int r4 = ~r4
            r6 = -1
            goto L1b
        L17:
            int[] r6 = r3.c
            r6 = r6[r4]
        L1b:
            java.lang.Object[] r7 = r3.b
            r7[r4] = r1
            int[] r3 = r3.c
            r3[r4] = r2
            boolean r3 = r1 instanceof androidx.compose.runtime.E
            r4 = 2
            if (r3 == 0) goto L90
            if (r6 == r2) goto L90
            r2 = r1
            androidx.compose.runtime.E r2 = (androidx.compose.runtime.E) r2
            androidx.compose.runtime.D r2 = r2.j()
            java.util.HashMap r3 = r0.l
            java.lang.Object r7 = r2.f
            r3.put(r1, r7)
            androidx.collection.C r2 = r2.e
            androidx.collection.I r3 = r0.k
            com.google.android.gms.internal.mlkit_vision_barcode.F4.e(r3, r1)
            java.lang.Object[] r7 = r2.b
            long[] r2 = r2.a
            int r8 = r2.length
            int r8 = r8 - r4
            if (r8 < 0) goto L90
            r10 = 0
        L48:
            r11 = r2[r10]
            long r13 = ~r11
            r15 = 7
            long r13 = r13 << r15
            long r13 = r13 & r11
            r15 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r13 = r13 & r15
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 == 0) goto L8b
            int r13 = r10 - r8
            int r13 = ~r13
            int r13 = r13 >>> 31
            r14 = 8
            int r13 = 8 - r13
            r15 = 0
        L62:
            if (r15 >= r13) goto L89
            r16 = 255(0xff, double:1.26E-321)
            long r16 = r11 & r16
            r18 = 128(0x80, double:6.3E-322)
            int r16 = (r16 > r18 ? 1 : (r16 == r18 ? 0 : -1))
            if (r16 >= 0) goto L85
            int r16 = r10 << 3
            int r16 = r16 + r15
            r16 = r7[r16]
            r9 = r16
            androidx.compose.runtime.snapshots.z r9 = (androidx.compose.runtime.snapshots.z) r9
            boolean r5 = r9 instanceof androidx.compose.runtime.snapshots.A
            if (r5 == 0) goto L82
            r5 = r9
            androidx.compose.runtime.snapshots.A r5 = (androidx.compose.runtime.snapshots.A) r5
            r5.h(r4)
        L82:
            com.google.android.gms.internal.mlkit_vision_barcode.F4.b(r3, r9, r1)
        L85:
            long r11 = r11 >> r14
            int r15 = r15 + 1
            goto L62
        L89:
            if (r13 != r14) goto L90
        L8b:
            if (r10 == r8) goto L90
            int r10 = r10 + 1
            goto L48
        L90:
            r2 = -1
            if (r6 != r2) goto La4
            boolean r2 = r1 instanceof androidx.compose.runtime.snapshots.A
            if (r2 == 0) goto L9d
            r2 = r1
            androidx.compose.runtime.snapshots.A r2 = (androidx.compose.runtime.snapshots.A) r2
            r2.h(r4)
        L9d:
            androidx.collection.I r2 = r0.e
            r3 = r23
            com.google.android.gms.internal.mlkit_vision_barcode.F4.b(r2, r1, r3)
        La4:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.u.c(java.lang.Object, int, java.lang.Object, androidx.collection.C):void");
    }

    public final void d(Object obj, Object obj2) {
        I i = this.e;
        F4.d(i, obj2, obj);
        if (!(obj2 instanceof androidx.compose.runtime.E) || i.c(obj2)) {
            return;
        }
        F4.e(this.k, obj2);
        this.l.remove(obj2);
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00aa  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e() {
        /*
            Method dump skipped, instructions count: 225
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.u.e():void");
    }
}
