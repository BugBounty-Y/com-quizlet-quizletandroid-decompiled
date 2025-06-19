package androidx.compose.ui.contentcapture;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewStructure;
import android.view.autofill.AutofillId;
import androidx.activity.K;
import androidx.activity.RunnableC0041m;
import androidx.collection.AbstractC0214l;
import androidx.collection.C0209g;
import androidx.collection.C0223v;
import androidx.collection.C0224w;
import androidx.compose.ui.platform.C0971v;
import androidx.compose.ui.platform.H0;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.platform.O0;
import androidx.compose.ui.platform.coreshims.d;
import androidx.compose.ui.platform.coreshims.e;
import androidx.compose.ui.platform.coreshims.i;
import androidx.compose.ui.semantics.o;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.channels.h;

/* loaded from: classes.dex */
public final class c implements InterfaceC1250k, View.OnAttachStateChangeListener {
    public final C0971v a;
    public final K b;
    public d c;
    public final C0223v d = new C0223v();
    public final C0224w e = new C0224w();
    public final long f = 100;
    public int g = 1;
    public boolean h = true;
    public final C0209g i = new C0209g(0);
    public final h j = D1.a(1, 6, null);
    public final Handler k = new Handler(Looper.getMainLooper());
    public C0223v l;
    public long m;
    public final C0223v n;
    public O0 o;
    public boolean p;
    public final RunnableC0041m q;

    public c(C0971v c0971v, K k) {
        this.a = c0971v;
        this.b = k;
        C0223v c0223v = AbstractC0214l.a;
        Intrinsics.e(c0223v, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.intObjectMapOf>");
        this.l = c0223v;
        this.n = new C0223v();
        o oVarA = c0971v.getSemanticsOwner().a();
        Intrinsics.e(c0223v, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.intObjectMapOf>");
        this.o = new O0(oVarA, c0223v);
        this.q = new RunnableC0041m(this, 27);
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0064 A[Catch: all -> 0x002e, TryCatch #1 {all -> 0x002e, blocks: (B:13:0x002a, B:25:0x004f, B:28:0x005c, B:30:0x0064, B:32:0x006d, B:33:0x0070, B:35:0x0074, B:36:0x007d, B:20:0x003d), top: B:48:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:37:0x008e -> B:25:0x004f). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r9 instanceof androidx.compose.ui.contentcapture.b
            if (r0 == 0) goto L13
            r0 = r9
            androidx.compose.ui.contentcapture.b r0 = (androidx.compose.ui.contentcapture.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.compose.ui.contentcapture.b r0 = new androidx.compose.ui.contentcapture.b
            r0.<init>(r8, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L41
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            kotlinx.coroutines.channels.c r2 = r0.k
            androidx.compose.ui.contentcapture.c r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2e
            goto L4f
        L2e:
            r9 = move-exception
            goto L9d
        L31:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L39:
            kotlinx.coroutines.channels.c r2 = r0.k
            androidx.compose.ui.contentcapture.c r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2e
            goto L5c
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlinx.coroutines.channels.h r9 = r8.j     // Catch: java.lang.Throwable -> L9b
            r9.getClass()     // Catch: java.lang.Throwable -> L9b
            kotlinx.coroutines.channels.c r2 = new kotlinx.coroutines.channels.c     // Catch: java.lang.Throwable -> L9b
            r2.<init>(r9)     // Catch: java.lang.Throwable -> L9b
            r5 = r8
        L4f:
            r0.j = r5     // Catch: java.lang.Throwable -> L2e
            r0.k = r2     // Catch: java.lang.Throwable -> L2e
            r0.n = r4     // Catch: java.lang.Throwable -> L2e
            java.lang.Object r9 = r2.b(r0)     // Catch: java.lang.Throwable -> L2e
            if (r9 != r1) goto L5c
            goto L90
        L5c:
            java.lang.Boolean r9 = (java.lang.Boolean) r9     // Catch: java.lang.Throwable -> L2e
            boolean r9 = r9.booleanValue()     // Catch: java.lang.Throwable -> L2e
            if (r9 == 0) goto L91
            r2.c()     // Catch: java.lang.Throwable -> L2e
            boolean r9 = r5.c()     // Catch: java.lang.Throwable -> L2e
            if (r9 == 0) goto L70
            r5.e()     // Catch: java.lang.Throwable -> L2e
        L70:
            boolean r9 = r5.p     // Catch: java.lang.Throwable -> L2e
            if (r9 != 0) goto L7d
            r5.p = r4     // Catch: java.lang.Throwable -> L2e
            android.os.Handler r9 = r5.k     // Catch: java.lang.Throwable -> L2e
            androidx.activity.m r6 = r5.q     // Catch: java.lang.Throwable -> L2e
            r9.post(r6)     // Catch: java.lang.Throwable -> L2e
        L7d:
            androidx.collection.g r9 = r5.i     // Catch: java.lang.Throwable -> L2e
            r9.clear()     // Catch: java.lang.Throwable -> L2e
            long r6 = r5.f     // Catch: java.lang.Throwable -> L2e
            r0.j = r5     // Catch: java.lang.Throwable -> L2e
            r0.k = r2     // Catch: java.lang.Throwable -> L2e
            r0.n = r3     // Catch: java.lang.Throwable -> L2e
            java.lang.Object r9 = kotlinx.coroutines.E.n(r6, r0)     // Catch: java.lang.Throwable -> L2e
            if (r9 != r1) goto L4f
        L90:
            return r1
        L91:
            androidx.collection.g r9 = r5.i
            r9.clear()
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L99:
            r5 = r8
            goto L9d
        L9b:
            r9 = move-exception
            goto L99
        L9d:
            androidx.collection.g r0 = r5.i
            r0.clear()
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.contentcapture.c.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final C0223v b() {
        if (this.h) {
            this.h = false;
            this.l = N.u(this.a.getSemanticsOwner());
            this.m = System.currentTimeMillis();
        }
        return this.l;
    }

    public final boolean c() {
        return this.c != null;
    }

    public final void e() {
        long j;
        long j2;
        char c;
        long j3;
        d dVar = this.c;
        if (dVar != null && Build.VERSION.SDK_INT >= 29) {
            C0223v c0223v = this.d;
            int i = c0223v.e;
            Object obj = dVar.a;
            String str = "TREAT_AS_VIEW_TREE_APPEARED";
            long j4 = -9187201950435737472L;
            View view = dVar.b;
            if (i != 0) {
                ArrayList arrayList = new ArrayList();
                Object[] objArr = c0223v.c;
                j2 = 255;
                long[] jArr = c0223v.a;
                int length = jArr.length - 2;
                if (length >= 0) {
                    int i2 = 0;
                    c = 7;
                    while (true) {
                        long j5 = jArr[i2];
                        if ((((~j5) << 7) & j5 & j4) != j4) {
                            int i3 = 8 - ((~(i2 - length)) >>> 31);
                            int i4 = 0;
                            while (i4 < i3) {
                                if ((j5 & 255) < 128) {
                                    j3 = j4;
                                    arrayList.add((i) objArr[(i2 << 3) + i4]);
                                } else {
                                    j3 = j4;
                                }
                                j5 >>= 8;
                                i4++;
                                j4 = j3;
                            }
                            j = j4;
                            if (i3 != 8) {
                                break;
                            }
                        } else {
                            j = j4;
                        }
                        if (i2 == length) {
                            break;
                        }
                        i2++;
                        j4 = j;
                    }
                } else {
                    j = -9187201950435737472L;
                    c = 7;
                }
                ArrayList arrayList2 = new ArrayList(arrayList.size());
                int size = arrayList.size();
                for (int i5 = 0; i5 < size; i5++) {
                    arrayList2.add(((i) arrayList.get(i5)).a);
                }
                int i6 = Build.VERSION.SDK_INT;
                if (i6 >= 34) {
                    androidx.compose.ui.platform.coreshims.c.a(H0.f(obj), arrayList2);
                } else {
                    if (i6 >= 29) {
                        ViewStructure viewStructureB = androidx.compose.ui.platform.coreshims.b.b(H0.f(obj), view);
                        androidx.compose.ui.platform.coreshims.a.a(viewStructureB).putBoolean("TREAT_AS_VIEW_TREE_APPEARING", true);
                        androidx.compose.ui.platform.coreshims.b.d(H0.f(obj), viewStructureB);
                        for (int i7 = 0; i7 < arrayList2.size(); i7++) {
                            androidx.compose.ui.platform.coreshims.b.d(H0.f(obj), (ViewStructure) arrayList2.get(i7));
                        }
                        ViewStructure viewStructureB2 = androidx.compose.ui.platform.coreshims.b.b(H0.f(obj), view);
                        str = "TREAT_AS_VIEW_TREE_APPEARED";
                        androidx.compose.ui.platform.coreshims.a.a(viewStructureB2).putBoolean(str, true);
                        androidx.compose.ui.platform.coreshims.b.d(H0.f(obj), viewStructureB2);
                    }
                    c0223v.a();
                }
                str = "TREAT_AS_VIEW_TREE_APPEARED";
                c0223v.a();
            } else {
                j = -9187201950435737472L;
                j2 = 255;
                c = 7;
            }
            C0224w c0224w = this.e;
            if (c0224w.d != 0) {
                ArrayList arrayList3 = new ArrayList();
                int[] iArr = c0224w.b;
                long[] jArr2 = c0224w.a;
                int length2 = jArr2.length - 2;
                if (length2 >= 0) {
                    int i8 = 0;
                    while (true) {
                        long j6 = jArr2[i8];
                        if ((((~j6) << c) & j6 & j) != j) {
                            int i9 = 8 - ((~(i8 - length2)) >>> 31);
                            for (int i10 = 0; i10 < i9; i10++) {
                                if ((j6 & j2) < 128) {
                                    arrayList3.add(Integer.valueOf(iArr[(i8 << 3) + i10]));
                                }
                                j6 >>= 8;
                            }
                            if (i9 != 8) {
                                break;
                            }
                        }
                        if (i8 == length2) {
                            break;
                        } else {
                            i8++;
                        }
                    }
                }
                ArrayList arrayList4 = new ArrayList(arrayList3.size());
                int size2 = arrayList3.size();
                for (int i11 = 0; i11 < size2; i11++) {
                    arrayList4.add(Long.valueOf(((Number) arrayList3.get(i11)).intValue()));
                }
                long[] jArrX0 = CollectionsKt.x0(arrayList4);
                int i12 = Build.VERSION.SDK_INT;
                if (i12 >= 34) {
                    androidx.compose.ui.platform.coreshims.b.f(H0.f(obj), e.a(view), jArrX0);
                } else if (i12 >= 29) {
                    ViewStructure viewStructureB3 = androidx.compose.ui.platform.coreshims.b.b(H0.f(obj), view);
                    androidx.compose.ui.platform.coreshims.a.a(viewStructureB3).putBoolean("TREAT_AS_VIEW_TREE_APPEARING", true);
                    androidx.compose.ui.platform.coreshims.b.d(H0.f(obj), viewStructureB3);
                    androidx.compose.ui.platform.coreshims.b.f(H0.f(obj), e.a(view), jArrX0);
                    ViewStructure viewStructureB4 = androidx.compose.ui.platform.coreshims.b.b(H0.f(obj), view);
                    androidx.compose.ui.platform.coreshims.a.a(viewStructureB4).putBoolean(str, true);
                    androidx.compose.ui.platform.coreshims.b.d(H0.f(obj), viewStructureB4);
                }
                c0224w.b();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x008f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(androidx.compose.ui.semantics.o r19, androidx.compose.ui.platform.O0 r20) {
        /*
            r18 = this;
            r0 = r18
            r1 = r19
            r2 = 4
            java.util.List r3 = androidx.compose.ui.semantics.o.h(r1, r2)
            int r4 = r3.size()
            r5 = 0
            r6 = r5
        Lf:
            if (r6 >= r4) goto L38
            java.lang.Object r7 = r3.get(r6)
            androidx.compose.ui.semantics.o r7 = (androidx.compose.ui.semantics.o) r7
            androidx.collection.v r8 = r0.b()
            int r9 = r7.g
            boolean r8 = r8.b(r9)
            if (r8 == 0) goto L33
            r8 = r20
            androidx.collection.w r9 = r8.b
            int r10 = r7.g
            boolean r9 = r9.c(r10)
            if (r9 != 0) goto L35
            r0.i(r7)
            goto L35
        L33:
            r8 = r20
        L35:
            int r6 = r6 + 1
            goto Lf
        L38:
            androidx.collection.v r3 = r0.n
            int[] r4 = r3.b
            long[] r6 = r3.a
            int r7 = r6.length
            int r7 = r7 + (-2)
            if (r7 < 0) goto L94
            r8 = r5
        L44:
            r9 = r6[r8]
            long r11 = ~r9
            r13 = 7
            long r11 = r11 << r13
            long r11 = r11 & r9
            r13 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r11 = r11 & r13
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 == 0) goto L8f
            int r11 = r8 - r7
            int r11 = ~r11
            int r11 = r11 >>> 31
            r12 = 8
            int r11 = 8 - r11
            r13 = r5
        L5e:
            if (r13 >= r11) goto L8d
            r14 = 255(0xff, double:1.26E-321)
            long r14 = r14 & r9
            r16 = 128(0x80, double:6.3E-322)
            int r14 = (r14 > r16 ? 1 : (r14 == r16 ? 0 : -1))
            if (r14 >= 0) goto L89
            int r14 = r8 << 3
            int r14 = r14 + r13
            r14 = r4[r14]
            androidx.collection.v r15 = r0.b()
            boolean r15 = r15.b(r14)
            if (r15 != 0) goto L89
            androidx.collection.v r15 = r0.d
            boolean r16 = r15.b(r14)
            if (r16 == 0) goto L84
            r15.g(r14)
            goto L89
        L84:
            androidx.collection.w r15 = r0.e
            r15.a(r14)
        L89:
            long r9 = r9 >> r12
            int r13 = r13 + 1
            goto L5e
        L8d:
            if (r11 != r12) goto L94
        L8f:
            if (r8 == r7) goto L94
            int r8 = r8 + 1
            goto L44
        L94:
            java.util.List r1 = androidx.compose.ui.semantics.o.h(r1, r2)
            int r2 = r1.size()
        L9c:
            if (r5 >= r2) goto Lce
            java.lang.Object r4 = r1.get(r5)
            androidx.compose.ui.semantics.o r4 = (androidx.compose.ui.semantics.o) r4
            androidx.collection.v r6 = r0.b()
            int r7 = r4.g
            boolean r6 = r6.b(r7)
            if (r6 == 0) goto Lcb
            int r6 = r4.g
            boolean r7 = r3.b(r6)
            if (r7 == 0) goto Lcb
            java.lang.Object r6 = r3.e(r6)
            if (r6 == 0) goto Lc4
            androidx.compose.ui.platform.O0 r6 = (androidx.compose.ui.platform.O0) r6
            r0.f(r4, r6)
            goto Lcb
        Lc4:
            java.lang.String r1 = "node not present in pruned tree before this change"
            com.google.android.gms.internal.mlkit_vision_barcode.W4.g(r1)
            r1 = 0
            throw r1
        Lcb:
            int r5 = r5 + 1
            goto L9c
        Lce:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.contentcapture.c.f(androidx.compose.ui.semantics.o, androidx.compose.ui.platform.O0):void");
    }

    public final void g(int i, String str) {
        d dVar;
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 29 && (dVar = this.c) != null) {
            long j = i;
            Object obj = dVar.a;
            AutofillId autofillIdA = i2 >= 29 ? androidx.compose.ui.platform.coreshims.b.a(H0.f(obj), e.a(dVar.b), j) : null;
            if (autofillIdA == null) {
                W4.g("Invalid content capture ID");
                throw null;
            }
            if (i2 >= 29) {
                androidx.compose.ui.platform.coreshims.b.e(H0.f(obj), autofillIdA, str);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00a2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h(androidx.compose.ui.semantics.o r22, androidx.compose.ui.platform.O0 r23) {
        /*
            Method dump skipped, instructions count: 224
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.contentcapture.c.h(androidx.compose.ui.semantics.o, androidx.compose.ui.platform.O0):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:117:0x021d, code lost:
    
        if (((r3 & ((~r3) << 6)) & (-9187201950435737472L)) == 0) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x021f, code lost:
    
        r15 = -1;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00a8 A[PHI: r10
  0x00a8: PHI (r10v5 android.view.autofill.AutofillId) = (r10v4 android.view.autofill.AutofillId), (r10v13 android.view.autofill.AutofillId) binds: [B:39:0x008c, B:44:0x00a4] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(androidx.compose.ui.semantics.o r21) {
        /*
            Method dump skipped, instructions count: 589
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.contentcapture.c.i(androidx.compose.ui.semantics.o):void");
    }

    public final void j(o oVar) {
        if (c()) {
            int i = oVar.g;
            C0223v c0223v = this.d;
            if (c0223v.b(i)) {
                c0223v.g(i);
            } else {
                this.e.a(i);
            }
            List listH = o.h(oVar, 4);
            int size = listH.size();
            for (int i2 = 0; i2 < size; i2++) {
                j((o) listH.get(i2));
            }
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J j) {
        this.c = (d) this.b.invoke();
        i(this.a.getSemanticsOwner().a());
        e();
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStop(J j) {
        j(this.a.getSemanticsOwner().a());
        e();
        this.c = null;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewAttachedToWindow(View view) {
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public final void onViewDetachedFromWindow(View view) {
        this.k.removeCallbacks(this.q);
        this.c = null;
    }
}
