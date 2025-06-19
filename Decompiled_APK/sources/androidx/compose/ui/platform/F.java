package androidx.compose.ui.platform;

import android.content.res.Resources;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Parcelable;
import android.os.SystemClock;
import android.os.Trace;
import android.util.Log;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.activity.RunnableC0041m;
import androidx.appcompat.view.menu.ViewOnAttachStateChangeListenerC0068e;
import androidx.collection.AbstractC0213k;
import androidx.collection.AbstractC0214l;
import androidx.collection.C0209g;
import androidx.collection.C0221t;
import androidx.collection.C0222u;
import androidx.collection.C0223v;
import androidx.collection.C0224w;
import androidx.compose.ui.text.C0995g;
import androidx.core.view.C1038b;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class F extends C1038b {
    public static final C0222u N;
    public C0223v A;
    public final C0224w B;
    public final C0221t C;
    public final C0221t D;
    public final String E;
    public final String F;
    public final com.google.android.gms.internal.appset.e G;
    public final C0223v H;
    public O0 I;
    public boolean J;
    public final RunnableC0041m K;
    public final ArrayList L;
    public final E M;
    public final C0971v d;
    public int e = Integer.MIN_VALUE;
    public final E f = new E(this, 0);
    public final AccessibilityManager g;
    public long h;
    public final AccessibilityManagerAccessibilityStateChangeListenerC0973w i;
    public final AccessibilityManagerTouchExplorationStateChangeListenerC0975x j;
    public List k;
    public final Handler l;
    public final A m;
    public int n;
    public androidx.core.view.accessibility.e o;
    public boolean p;
    public final C0223v q;
    public final C0223v r;
    public final androidx.collection.W s;
    public final androidx.collection.W t;
    public int u;
    public Integer v;
    public final C0209g w;
    public final kotlinx.coroutines.channels.h x;
    public boolean y;
    public C z;

    static {
        int i;
        int[] elements = {R.id.accessibility_custom_action_0, R.id.accessibility_custom_action_1, R.id.accessibility_custom_action_2, R.id.accessibility_custom_action_3, R.id.accessibility_custom_action_4, R.id.accessibility_custom_action_5, R.id.accessibility_custom_action_6, R.id.accessibility_custom_action_7, R.id.accessibility_custom_action_8, R.id.accessibility_custom_action_9, R.id.accessibility_custom_action_10, R.id.accessibility_custom_action_11, R.id.accessibility_custom_action_12, R.id.accessibility_custom_action_13, R.id.accessibility_custom_action_14, R.id.accessibility_custom_action_15, R.id.accessibility_custom_action_16, R.id.accessibility_custom_action_17, R.id.accessibility_custom_action_18, R.id.accessibility_custom_action_19, R.id.accessibility_custom_action_20, R.id.accessibility_custom_action_21, R.id.accessibility_custom_action_22, R.id.accessibility_custom_action_23, R.id.accessibility_custom_action_24, R.id.accessibility_custom_action_25, R.id.accessibility_custom_action_26, R.id.accessibility_custom_action_27, R.id.accessibility_custom_action_28, R.id.accessibility_custom_action_29, R.id.accessibility_custom_action_30, R.id.accessibility_custom_action_31};
        int i2 = AbstractC0213k.a;
        Intrinsics.checkNotNullParameter(elements, "elements");
        C0222u c0222u = new C0222u(32);
        int i3 = c0222u.b;
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (i3 < 0 || i3 > (i = c0222u.b)) {
            androidx.collection.internal.a.d("");
            throw null;
        }
        c0222u.b(i + 32);
        int[] iArr = c0222u.a;
        int i4 = c0222u.b;
        if (i3 != i4) {
            C4930v.e(i3 + 32, i3, i4, iArr, iArr);
        }
        C4930v.i(i3, 0, 12, elements, iArr);
        c0222u.b += 32;
        N = c0222u;
    }

    /* JADX WARN: Type inference failed for: r2v4, types: [androidx.compose.ui.platform.w] */
    /* JADX WARN: Type inference failed for: r2v5, types: [androidx.compose.ui.platform.x] */
    public F(C0971v c0971v) {
        this.d = c0971v;
        Object systemService = c0971v.getContext().getSystemService("accessibility");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.accessibility.AccessibilityManager");
        AccessibilityManager accessibilityManager = (AccessibilityManager) systemService;
        this.g = accessibilityManager;
        this.h = 100L;
        this.i = new AccessibilityManager.AccessibilityStateChangeListener() { // from class: androidx.compose.ui.platform.w
            @Override // android.view.accessibility.AccessibilityManager.AccessibilityStateChangeListener
            public final void onAccessibilityStateChanged(boolean z) {
                F f = this.a;
                f.k = z ? f.g.getEnabledAccessibilityServiceList(-1) : kotlin.collections.K.a;
            }
        };
        this.j = new AccessibilityManager.TouchExplorationStateChangeListener() { // from class: androidx.compose.ui.platform.x
            @Override // android.view.accessibility.AccessibilityManager.TouchExplorationStateChangeListener
            public final void onTouchExplorationStateChanged(boolean z) {
                F f = this.a;
                f.k = f.g.getEnabledAccessibilityServiceList(-1);
            }
        };
        this.k = accessibilityManager.getEnabledAccessibilityServiceList(-1);
        this.l = new Handler(Looper.getMainLooper());
        this.m = new A(this, 0);
        this.n = Integer.MIN_VALUE;
        this.q = new C0223v();
        this.r = new C0223v();
        this.s = new androidx.collection.W(0);
        this.t = new androidx.collection.W(0);
        this.u = -1;
        this.w = new C0209g(0);
        this.x = D1.a(1, 6, null);
        this.y = true;
        C0223v c0223v = AbstractC0214l.a;
        Intrinsics.e(c0223v, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.intObjectMapOf>");
        this.A = c0223v;
        this.B = new C0224w();
        this.C = new C0221t();
        this.D = new C0221t();
        this.E = "android.view.accessibility.extra.EXTRA_DATA_TEST_TRAVERSALBEFORE_VAL";
        this.F = "android.view.accessibility.extra.EXTRA_DATA_TEST_TRAVERSALAFTER_VAL";
        this.G = new com.google.android.gms.internal.appset.e(3);
        this.H = new C0223v();
        androidx.compose.ui.semantics.o oVarA = c0971v.getSemanticsOwner().a();
        Intrinsics.e(c0223v, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.intObjectMapOf>");
        this.I = new O0(oVarA, c0223v);
        c0971v.addOnAttachStateChangeListener(new ViewOnAttachStateChangeListenerC0068e(this, 2));
        this.K = new RunnableC0041m(this, 29);
        this.L = new ArrayList();
        this.M = new E(this, 1);
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v2, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public static final boolean A(androidx.compose.ui.semantics.i iVar, float f) {
        ?? r2 = iVar.a;
        if (f >= DefinitionKt.NO_Float_VALUE || ((Number) r2.invoke()).floatValue() <= DefinitionKt.NO_Float_VALUE) {
            return f > DefinitionKt.NO_Float_VALUE && ((Number) r2.invoke()).floatValue() < ((Number) iVar.b.invoke()).floatValue();
        }
        return true;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r3v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public static final boolean B(androidx.compose.ui.semantics.i iVar) {
        ?? r0 = iVar.a;
        if (((Number) r0.invoke()).floatValue() > DefinitionKt.NO_Float_VALUE) {
            return true;
        }
        ((Number) r0.invoke()).floatValue();
        ((Number) iVar.b.invoke()).floatValue();
        return false;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public static final boolean C(androidx.compose.ui.semantics.i iVar) {
        ?? r0 = iVar.a;
        if (((Number) r0.invoke()).floatValue() < ((Number) iVar.b.invoke()).floatValue()) {
            return true;
        }
        ((Number) r0.invoke()).floatValue();
        return false;
    }

    public static /* synthetic */ void H(F f, int i, int i2, Integer num, int i3) {
        if ((i3 & 4) != 0) {
            num = null;
        }
        f.G(i, i2, num, null);
    }

    public static CharSequence P(CharSequence charSequence) {
        if (charSequence.length() != 0) {
            int i = 100000;
            if (charSequence.length() > 100000) {
                if (Character.isHighSurrogate(charSequence.charAt(99999)) && Character.isLowSurrogate(charSequence.charAt(100000))) {
                    i = 99999;
                }
                CharSequence charSequenceSubSequence = charSequence.subSequence(0, i);
                Intrinsics.e(charSequenceSubSequence, "null cannot be cast to non-null type T of androidx.compose.ui.platform.AndroidComposeViewAccessibilityDelegateCompat.trimToSize");
                return charSequenceSubSequence;
            }
        }
        return charSequence;
    }

    public static boolean u(androidx.compose.ui.semantics.o oVar) {
        Object obj = oVar.d.a.get(androidx.compose.ui.semantics.r.B);
        if (obj == null) {
            obj = null;
        }
        androidx.compose.ui.state.a aVar = (androidx.compose.ui.state.a) obj;
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.s;
        LinkedHashMap linkedHashMap = oVar.d.a;
        Object obj2 = linkedHashMap.get(uVar);
        if (obj2 == null) {
            obj2 = null;
        }
        androidx.compose.ui.semantics.h hVar = (androidx.compose.ui.semantics.h) obj2;
        boolean z = aVar != null;
        Object obj3 = linkedHashMap.get(androidx.compose.ui.semantics.r.A);
        if (((Boolean) (obj3 != null ? obj3 : null)) == null || (hVar != null && hVar.a == 4)) {
            return z;
        }
        return true;
    }

    public static String w(androidx.compose.ui.semantics.o oVar) {
        C0995g c0995g;
        if (oVar != null) {
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.a;
            androidx.compose.ui.semantics.k kVar = oVar.d;
            LinkedHashMap linkedHashMap = kVar.a;
            if (linkedHashMap.containsKey(uVar)) {
                return U5.b((List) kVar.a(uVar), ",", null, 62);
            }
            androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.x;
            if (linkedHashMap.containsKey(uVar2)) {
                Object obj = linkedHashMap.get(uVar2);
                if (obj == null) {
                    obj = null;
                }
                C0995g c0995g2 = (C0995g) obj;
                if (c0995g2 != null) {
                    return c0995g2.a;
                }
            } else {
                Object obj2 = linkedHashMap.get(androidx.compose.ui.semantics.r.u);
                if (obj2 == null) {
                    obj2 = null;
                }
                List list = (List) obj2;
                if (list != null && (c0995g = (C0995g) CollectionsKt.firstOrNull(list)) != null) {
                    return c0995g.a;
                }
            }
        }
        return null;
    }

    public final int D(int i) {
        if (i == this.d.getSemanticsOwner().a().g) {
            return -1;
        }
        return i;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0088  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void E(androidx.compose.ui.semantics.o r20, androidx.compose.ui.platform.O0 r21) {
        /*
            r19 = this;
            r0 = r19
            r1 = r20
            r2 = r21
            int[] r3 = androidx.collection.AbstractC0215m.a
            androidx.collection.w r3 = new androidx.collection.w
            r3.<init>()
            r4 = 4
            java.util.List r5 = androidx.compose.ui.semantics.o.h(r1, r4)
            int r6 = r5.size()
            r7 = 0
            r8 = r7
        L18:
            androidx.compose.ui.node.E r9 = r1.c
            if (r8 >= r6) goto L42
            java.lang.Object r10 = r5.get(r8)
            androidx.compose.ui.semantics.o r10 = (androidx.compose.ui.semantics.o) r10
            androidx.collection.v r11 = r0.t()
            int r12 = r10.g
            boolean r11 = r11.b(r12)
            if (r11 == 0) goto L3f
            androidx.collection.w r11 = r2.b
            int r10 = r10.g
            boolean r11 = r11.c(r10)
            if (r11 != 0) goto L3c
            r0.z(r9)
            return
        L3c:
            r3.a(r10)
        L3f:
            int r8 = r8 + 1
            goto L18
        L42:
            androidx.collection.w r2 = r2.b
            int[] r5 = r2.b
            long[] r2 = r2.a
            int r6 = r2.length
            int r6 = r6 + (-2)
            if (r6 < 0) goto L8d
            r8 = r7
        L4e:
            r10 = r2[r8]
            long r12 = ~r10
            r14 = 7
            long r12 = r12 << r14
            long r12 = r12 & r10
            r14 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r12 = r12 & r14
            int r12 = (r12 > r14 ? 1 : (r12 == r14 ? 0 : -1))
            if (r12 == 0) goto L88
            int r12 = r8 - r6
            int r12 = ~r12
            int r12 = r12 >>> 31
            r13 = 8
            int r12 = 8 - r12
            r14 = r7
        L68:
            if (r14 >= r12) goto L86
            r15 = 255(0xff, double:1.26E-321)
            long r15 = r15 & r10
            r17 = 128(0x80, double:6.3E-322)
            int r15 = (r15 > r17 ? 1 : (r15 == r17 ? 0 : -1))
            if (r15 >= 0) goto L82
            int r15 = r8 << 3
            int r15 = r15 + r14
            r15 = r5[r15]
            boolean r15 = r3.c(r15)
            if (r15 != 0) goto L82
            r0.z(r9)
            return
        L82:
            long r10 = r10 >> r13
            int r14 = r14 + 1
            goto L68
        L86:
            if (r12 != r13) goto L8d
        L88:
            if (r8 == r6) goto L8d
            int r8 = r8 + 1
            goto L4e
        L8d:
            java.util.List r1 = androidx.compose.ui.semantics.o.h(r1, r4)
            int r2 = r1.size()
        L95:
            if (r7 >= r2) goto Lbc
            java.lang.Object r3 = r1.get(r7)
            androidx.compose.ui.semantics.o r3 = (androidx.compose.ui.semantics.o) r3
            androidx.collection.v r4 = r0.t()
            int r5 = r3.g
            boolean r4 = r4.b(r5)
            if (r4 == 0) goto Lb9
            androidx.collection.v r4 = r0.H
            int r5 = r3.g
            java.lang.Object r4 = r4.e(r5)
            kotlin.jvm.internal.Intrinsics.d(r4)
            androidx.compose.ui.platform.O0 r4 = (androidx.compose.ui.platform.O0) r4
            r0.E(r3, r4)
        Lb9:
            int r7 = r7 + 1
            goto L95
        Lbc:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.E(androidx.compose.ui.semantics.o, androidx.compose.ui.platform.O0):void");
    }

    public final boolean F(AccessibilityEvent accessibilityEvent) {
        if (!x()) {
            return false;
        }
        if (accessibilityEvent.getEventType() == 2048 || accessibilityEvent.getEventType() == 32768) {
            this.p = true;
        }
        try {
            return ((Boolean) this.f.invoke(accessibilityEvent)).booleanValue();
        } finally {
            this.p = false;
        }
    }

    public final boolean G(int i, int i2, Integer num, List list) {
        if (i == Integer.MIN_VALUE || !x()) {
            return false;
        }
        AccessibilityEvent accessibilityEventO = o(i, i2);
        if (num != null) {
            accessibilityEventO.setContentChangeTypes(num.intValue());
        }
        if (list != null) {
            accessibilityEventO.setContentDescription(U5.b(list, ",", null, 62));
        }
        Trace.beginSection("sendEvent");
        try {
            return F(accessibilityEventO);
        } finally {
            Trace.endSection();
        }
    }

    public final void I(int i, int i2, String str) {
        AccessibilityEvent accessibilityEventO = o(D(i), 32);
        accessibilityEventO.setContentChangeTypes(i2);
        if (str != null) {
            accessibilityEventO.getText().add(str);
        }
        F(accessibilityEventO);
    }

    public final void J(int i) {
        C c = this.z;
        if (c != null) {
            androidx.compose.ui.semantics.o oVar = c.a;
            if (i != oVar.g) {
                return;
            }
            if (SystemClock.uptimeMillis() - c.f <= 1000) {
                AccessibilityEvent accessibilityEventO = o(D(oVar.g), 131072);
                accessibilityEventO.setFromIndex(c.d);
                accessibilityEventO.setToIndex(c.e);
                accessibilityEventO.setAction(c.b);
                accessibilityEventO.setMovementGranularity(c.c);
                accessibilityEventO.getText().add(w(oVar));
                F(accessibilityEventO);
            }
        }
        this.z = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:225:0x04f1  */
    /* JADX WARN: Removed duplicated region for block: B:251:0x0567  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x05bb  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00d7  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00fb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void K(androidx.collection.C0223v r38) {
        /*
            Method dump skipped, instructions count: 1547
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.K(androidx.collection.v):void");
    }

    public final void L(androidx.compose.ui.node.E e, C0224w c0224w) {
        androidx.compose.ui.semantics.k kVarO;
        if (e.E() && !this.d.getAndroidViewsHandler$ui_release().getLayoutNodeToHolder().containsKey(e)) {
            androidx.compose.ui.node.E e2 = null;
            if (!e.w.h(8)) {
                e = e.s();
                while (true) {
                    if (e == null) {
                        e = null;
                        break;
                    } else if (e.w.h(8)) {
                        break;
                    } else {
                        e = e.s();
                    }
                }
            }
            if (e == null || (kVarO = e.o()) == null) {
                return;
            }
            if (!kVarO.b) {
                androidx.compose.ui.node.E eS = e.s();
                while (true) {
                    if (eS != null) {
                        androidx.compose.ui.semantics.k kVarO2 = eS.o();
                        if (kVarO2 != null && kVarO2.b) {
                            e2 = eS;
                            break;
                        }
                        eS = eS.s();
                    } else {
                        break;
                    }
                }
                if (e2 != null) {
                    e = e2;
                }
            }
            int i = e.b;
            if (c0224w.a(i)) {
                H(this, D(i), 2048, 1, 8);
            }
        }
    }

    /* JADX WARN: Type inference failed for: r0v13, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v18, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r0v8, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public final void M(androidx.compose.ui.node.E e) {
        if (e.E() && !this.d.getAndroidViewsHandler$ui_release().getLayoutNodeToHolder().containsKey(e)) {
            int i = e.b;
            androidx.compose.ui.semantics.i iVar = (androidx.compose.ui.semantics.i) this.q.e(i);
            androidx.compose.ui.semantics.i iVar2 = (androidx.compose.ui.semantics.i) this.r.e(i);
            if (iVar == null && iVar2 == null) {
                return;
            }
            AccessibilityEvent accessibilityEventO = o(i, 4096);
            if (iVar != null) {
                accessibilityEventO.setScrollX((int) ((Number) iVar.a.invoke()).floatValue());
                accessibilityEventO.setMaxScrollX((int) ((Number) iVar.b.invoke()).floatValue());
            }
            if (iVar2 != null) {
                accessibilityEventO.setScrollY((int) ((Number) iVar2.a.invoke()).floatValue());
                accessibilityEventO.setMaxScrollY((int) ((Number) iVar2.b.invoke()).floatValue());
            }
            F(accessibilityEventO);
        }
    }

    public final boolean N(androidx.compose.ui.semantics.o oVar, int i, int i2, boolean z) {
        String strW;
        androidx.compose.ui.semantics.k kVar = oVar.d;
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.j.h;
        if (kVar.a.containsKey(uVar) && N.l(oVar)) {
            kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) ((androidx.compose.ui.semantics.a) oVar.d.a(uVar)).b;
            if (cVar != null) {
                return ((Boolean) cVar.invoke(Integer.valueOf(i), Integer.valueOf(i2), Boolean.valueOf(z))).booleanValue();
            }
        } else if ((i != i2 || i2 != this.u) && (strW = w(oVar)) != null) {
            if (i < 0 || i != i2 || i2 > strW.length()) {
                i = -1;
            }
            this.u = i;
            boolean z2 = strW.length() > 0;
            int i3 = oVar.g;
            F(p(D(i3), z2 ? Integer.valueOf(this.u) : null, z2 ? Integer.valueOf(this.u) : null, z2 ? Integer.valueOf(strW.length()) : null, strW));
            J(i3);
            return true;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x00be  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.ArrayList O(java.util.ArrayList r19, boolean r20) {
        /*
            Method dump skipped, instructions count: 341
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.O(java.util.ArrayList, boolean):java.util.ArrayList");
    }

    /* JADX WARN: Code restructure failed: missing block: B:53:0x014f, code lost:
    
        r28 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0159, code lost:
    
        if (((r7 & ((~r7) << 6)) & r22) == 0) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x015b, code lost:
    
        r25 = -1;
     */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0063  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Q() {
        /*
            Method dump skipped, instructions count: 548
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.Q():void");
    }

    @Override // androidx.core.view.C1038b
    public final com.airbnb.lottie.network.c b(View view) {
        return this.m;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void j(int i, androidx.core.view.accessibility.e eVar, String str, Bundle bundle) {
        androidx.compose.ui.semantics.o oVar;
        RectF rectF;
        P0 p0 = (P0) t().e(i);
        if (p0 == null || (oVar = p0.a) == null) {
            return;
        }
        String strW = w(oVar);
        boolean zB = Intrinsics.b(str, this.E);
        AccessibilityNodeInfo accessibilityNodeInfo = eVar.a;
        if (zB) {
            int iD = this.C.d(i);
            if (iD != -1) {
                accessibilityNodeInfo.getExtras().putInt(str, iD);
                return;
            }
            return;
        }
        if (Intrinsics.b(str, this.F)) {
            int iD2 = this.D.d(i);
            if (iD2 != -1) {
                accessibilityNodeInfo.getExtras().putInt(str, iD2);
                return;
            }
            return;
        }
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.j.a;
        androidx.compose.ui.semantics.k kVar = oVar.d;
        LinkedHashMap linkedHashMap = kVar.a;
        androidx.compose.ui.node.a0 a0Var = null;
        if (!linkedHashMap.containsKey(uVar) || bundle == null || !Intrinsics.b(str, "android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_KEY")) {
            androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.t;
            if (!linkedHashMap.containsKey(uVar2) || bundle == null || !Intrinsics.b(str, "androidx.compose.ui.semantics.testTag")) {
                if (Intrinsics.b(str, "androidx.compose.ui.semantics.id")) {
                    accessibilityNodeInfo.getExtras().putInt(str, oVar.g);
                    return;
                }
                return;
            } else {
                Object obj = linkedHashMap.get(uVar2);
                String str2 = (String) (obj == null ? null : obj);
                if (str2 != null) {
                    accessibilityNodeInfo.getExtras().putCharSequence(str, str2);
                    return;
                }
                return;
            }
        }
        int i2 = bundle.getInt("android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_ARG_START_INDEX", -1);
        int i3 = bundle.getInt("android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_ARG_LENGTH", -1);
        if (i3 > 0 && i2 >= 0) {
            if (i2 < (strW != null ? strW.length() : SubsamplingScaleImageView.TILE_SIZE_AUTO)) {
                androidx.compose.ui.text.H hW = N.w(kVar);
                if (hW == null) {
                    return;
                }
                ArrayList arrayList = new ArrayList();
                int i4 = 0;
                while (i4 < i3) {
                    int i5 = i2 + i4;
                    if (i5 >= hW.a.a.a.length()) {
                        arrayList.add(a0Var);
                    } else {
                        androidx.compose.ui.geometry.c cVarB = hW.b(i5);
                        androidx.compose.ui.node.a0 a0VarC = oVar.c();
                        long jU = 0;
                        if (a0VarC != null) {
                            if (!a0VarC.W0().m) {
                                a0VarC = a0Var;
                            }
                            if (a0VarC != null) {
                                jU = a0VarC.U(0L);
                            }
                        }
                        androidx.compose.ui.geometry.c cVarJ = cVarB.j(jU);
                        androidx.compose.ui.geometry.c cVarE = oVar.e();
                        androidx.compose.ui.geometry.c cVarF = cVarJ.h(cVarE) ? cVarJ.f(cVarE) : a0Var;
                        if (cVarF != 0) {
                            long jC = Q4.c(cVarF.a, cVarF.b);
                            C0971v c0971v = this.d;
                            long jP = c0971v.p(jC);
                            long jP2 = c0971v.p(Q4.c(cVarF.c, cVarF.d));
                            rectF = new RectF(androidx.compose.ui.geometry.b.d(jP), androidx.compose.ui.geometry.b.e(jP), androidx.compose.ui.geometry.b.d(jP2), androidx.compose.ui.geometry.b.e(jP2));
                        } else {
                            rectF = null;
                        }
                        arrayList.add(rectF);
                    }
                    i4++;
                    a0Var = null;
                }
                accessibilityNodeInfo.getExtras().putParcelableArray(str, (Parcelable[]) arrayList.toArray(new RectF[0]));
                return;
            }
        }
        Log.e("AccessibilityDelegate", "Invalid arguments for accessibility character locations");
    }

    public final Rect k(P0 p0) {
        Rect rect = p0.b;
        long jC = Q4.c(rect.left, rect.top);
        C0971v c0971v = this.d;
        long jP = c0971v.p(jC);
        long jP2 = c0971v.p(Q4.c(rect.right, rect.bottom));
        return new Rect((int) Math.floor(androidx.compose.ui.geometry.b.d(jP)), (int) Math.floor(androidx.compose.ui.geometry.b.e(jP)), (int) Math.ceil(androidx.compose.ui.geometry.b.d(jP2)), (int) Math.ceil(androidx.compose.ui.geometry.b.e(jP2)));
    }

    /* JADX WARN: Code restructure failed: missing block: B:41:0x00be, code lost:
    
        if (kotlinx.coroutines.E.n(r7, r0) == r1) goto L42;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0074 A[Catch: all -> 0x0031, TRY_LEAVE, TryCatch #0 {all -> 0x0031, blocks: (B:13:0x002c, B:25:0x0059, B:29:0x006c, B:31:0x0074, B:34:0x007f, B:36:0x0084, B:37:0x0093, B:39:0x009a, B:40:0x00a3, B:20:0x0042), top: B:51:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:33:0x007d -> B:43:0x00c1). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:41:0x00be -> B:43:0x00c1). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object l(kotlin.coroutines.jvm.internal.c r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 214
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.l(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00a5  */
    /* JADX WARN: Type inference failed for: r15v7, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r4v10, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m(boolean r20, long r21, int r23) {
        /*
            Method dump skipped, instructions count: 222
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.m(boolean, long, int):boolean");
    }

    public final void n() {
        Trace.beginSection("sendAccessibilitySemanticsStructureChangeEvents");
        try {
            if (x()) {
                E(this.d.getSemanticsOwner().a(), this.I);
            }
            Unit unit = Unit.a;
            Trace.endSection();
            Trace.beginSection("sendSemanticsPropertyChangeEvents");
            try {
                K(t());
                Trace.endSection();
                Trace.beginSection("updateSemanticsNodesCopyAndPanes");
                try {
                    Q();
                } finally {
                }
            } finally {
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final AccessibilityEvent o(int i, int i2) {
        P0 p0;
        AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain(i2);
        accessibilityEventObtain.setEnabled(true);
        accessibilityEventObtain.setClassName("android.view.View");
        C0971v c0971v = this.d;
        accessibilityEventObtain.setPackageName(c0971v.getContext().getPackageName());
        accessibilityEventObtain.setSource(c0971v, i);
        if (x() && (p0 = (P0) t().e(i)) != null) {
            accessibilityEventObtain.setPassword(p0.a.d.a.containsKey(androidx.compose.ui.semantics.r.C));
        }
        return accessibilityEventObtain;
    }

    public final AccessibilityEvent p(int i, Integer num, Integer num2, Integer num3, CharSequence charSequence) {
        AccessibilityEvent accessibilityEventO = o(i, 8192);
        if (num != null) {
            accessibilityEventO.setFromIndex(num.intValue());
        }
        if (num2 != null) {
            accessibilityEventO.setToIndex(num2.intValue());
        }
        if (num3 != null) {
            accessibilityEventO.setItemCount(num3.intValue());
        }
        if (charSequence != null) {
            accessibilityEventO.getText().add(charSequence);
        }
        return accessibilityEventO;
    }

    public final void q(androidx.compose.ui.semantics.o oVar, ArrayList arrayList, C0223v c0223v) {
        boolean zP = N.p(oVar);
        Object obj = oVar.d.a.get(androidx.compose.ui.semantics.r.l);
        if (obj == null) {
            obj = Boolean.FALSE;
        }
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        int i = oVar.g;
        if ((zBooleanValue || y(oVar)) && t().b(i)) {
            arrayList.add(oVar);
        }
        if (zBooleanValue) {
            c0223v.h(i, O(CollectionsKt.y0(androidx.compose.ui.semantics.o.h(oVar, 7)), zP));
            return;
        }
        List listH = androidx.compose.ui.semantics.o.h(oVar, 7);
        int size = listH.size();
        for (int i2 = 0; i2 < size; i2++) {
            q((androidx.compose.ui.semantics.o) listH.get(i2), arrayList, c0223v);
        }
    }

    public final int r(androidx.compose.ui.semantics.o oVar) {
        androidx.compose.ui.semantics.k kVar = oVar.d;
        if (!kVar.a.containsKey(androidx.compose.ui.semantics.r.a)) {
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.y;
            androidx.compose.ui.semantics.k kVar2 = oVar.d;
            if (kVar2.a.containsKey(uVar)) {
                return (int) (4294967295L & ((androidx.compose.ui.text.K) kVar2.a(uVar)).a);
            }
        }
        return this.u;
    }

    public final int s(androidx.compose.ui.semantics.o oVar) {
        androidx.compose.ui.semantics.k kVar = oVar.d;
        if (!kVar.a.containsKey(androidx.compose.ui.semantics.r.a)) {
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.y;
            androidx.compose.ui.semantics.k kVar2 = oVar.d;
            if (kVar2.a.containsKey(uVar)) {
                return (int) (((androidx.compose.ui.text.K) kVar2.a(uVar)).a >> 32);
            }
        }
        return this.u;
    }

    public final C0223v t() {
        if (this.y) {
            this.y = false;
            this.A = N.u(this.d.getSemanticsOwner());
            if (x()) {
                C0221t c0221t = this.C;
                c0221t.a();
                C0221t c0221t2 = this.D;
                c0221t2.a();
                P0 p0 = (P0) t().e(-1);
                androidx.compose.ui.semantics.o oVar = p0 != null ? p0.a : null;
                Intrinsics.d(oVar);
                ArrayList arrayListO = O(kotlin.collections.B.k(oVar), N.p(oVar));
                int i = kotlin.collections.B.i(arrayListO);
                int i2 = 1;
                if (1 <= i) {
                    while (true) {
                        int i3 = ((androidx.compose.ui.semantics.o) arrayListO.get(i2 - 1)).g;
                        int i4 = ((androidx.compose.ui.semantics.o) arrayListO.get(i2)).g;
                        c0221t.f(i3, i4);
                        c0221t2.f(i4, i3);
                        if (i2 == i) {
                            break;
                        }
                        i2++;
                    }
                }
            }
        }
        return this.A;
    }

    public final String v(androidx.compose.ui.semantics.o oVar) throws Resources.NotFoundException {
        Object string = oVar.d.a.get(androidx.compose.ui.semantics.r.b);
        String string2 = null;
        if (string == null) {
            string = null;
        }
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.B;
        androidx.compose.ui.semantics.k kVar = oVar.d;
        LinkedHashMap linkedHashMap = kVar.a;
        Object obj = linkedHashMap.get(uVar);
        if (obj == null) {
            obj = null;
        }
        androidx.compose.ui.state.a aVar = (androidx.compose.ui.state.a) obj;
        Object obj2 = linkedHashMap.get(androidx.compose.ui.semantics.r.s);
        if (obj2 == null) {
            obj2 = null;
        }
        androidx.compose.ui.semantics.h hVar = (androidx.compose.ui.semantics.h) obj2;
        C0971v c0971v = this.d;
        if (aVar != null) {
            int iOrdinal = aVar.ordinal();
            if (iOrdinal != 0) {
                if (iOrdinal != 1) {
                    if (iOrdinal == 2 && string == null) {
                        string = c0971v.getContext().getResources().getString(R.string.indeterminate);
                    }
                } else if (hVar != null && hVar.a == 2 && string == null) {
                    string = c0971v.getContext().getResources().getString(R.string.state_off);
                }
            } else if (hVar != null && hVar.a == 2 && string == null) {
                string = c0971v.getContext().getResources().getString(R.string.state_on);
            }
        }
        Object obj3 = linkedHashMap.get(androidx.compose.ui.semantics.r.A);
        if (obj3 == null) {
            obj3 = null;
        }
        Boolean bool = (Boolean) obj3;
        if (bool != null) {
            boolean zBooleanValue = bool.booleanValue();
            if ((hVar == null || hVar.a != 4) && string == null) {
                string = zBooleanValue ? c0971v.getContext().getResources().getString(R.string.selected) : c0971v.getContext().getResources().getString(R.string.not_selected);
            }
        }
        Object obj4 = linkedHashMap.get(androidx.compose.ui.semantics.r.c);
        if (obj4 == null) {
            obj4 = null;
        }
        androidx.compose.ui.semantics.g gVar = (androidx.compose.ui.semantics.g) obj4;
        if (gVar != null) {
            if (gVar != androidx.compose.ui.semantics.g.c) {
                if (string == null) {
                    kotlin.ranges.f fVar = gVar.b;
                    float f = fVar.b;
                    float f2 = fVar.a;
                    float f3 = f - f2 == DefinitionKt.NO_Float_VALUE ? 0.0f : (gVar.a - f2) / (fVar.b - f2);
                    if (f3 < DefinitionKt.NO_Float_VALUE) {
                        f3 = 0.0f;
                    }
                    if (f3 > 1.0f) {
                        f3 = 1.0f;
                    }
                    string = c0971v.getContext().getResources().getString(R.string.template_percent, Integer.valueOf(f3 == DefinitionKt.NO_Float_VALUE ? 0 : f3 == 1.0f ? 100 : kotlin.ranges.l.c(Math.round(f3 * 100), 1, 99)));
                }
            } else if (string == null) {
                string = c0971v.getContext().getResources().getString(R.string.in_progress);
            }
        }
        androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.r.x;
        if (linkedHashMap.containsKey(uVar2)) {
            androidx.compose.ui.semantics.k kVarI = new androidx.compose.ui.semantics.o(oVar.a, true, oVar.c, kVar).i();
            androidx.compose.ui.semantics.u uVar3 = androidx.compose.ui.semantics.r.a;
            LinkedHashMap linkedHashMap2 = kVarI.a;
            Object obj5 = linkedHashMap2.get(uVar3);
            if (obj5 == null) {
                obj5 = null;
            }
            Collection collection = (Collection) obj5;
            if (collection == null || collection.isEmpty()) {
                Object obj6 = linkedHashMap2.get(androidx.compose.ui.semantics.r.u);
                if (obj6 == null) {
                    obj6 = null;
                }
                Collection collection2 = (Collection) obj6;
                if (collection2 == null || collection2.isEmpty()) {
                    Object obj7 = linkedHashMap2.get(uVar2);
                    if (obj7 == null) {
                        obj7 = null;
                    }
                    CharSequence charSequence = (CharSequence) obj7;
                    if (charSequence == null || charSequence.length() == 0) {
                        string2 = c0971v.getContext().getResources().getString(R.string.state_empty);
                    }
                }
            }
            string = string2;
        }
        return (String) string;
    }

    public final boolean x() {
        return this.g.isEnabled() && !this.k.isEmpty();
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0056  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean y(androidx.compose.ui.semantics.o r8) {
        /*
            r7 = this;
            androidx.compose.ui.semantics.k r0 = r8.d
            androidx.compose.ui.semantics.u r1 = androidx.compose.ui.semantics.r.a
            java.util.LinkedHashMap r0 = r0.a
            java.lang.Object r0 = r0.get(r1)
            r1 = 0
            if (r0 != 0) goto Le
            r0 = r1
        Le:
            java.util.List r0 = (java.util.List) r0
            if (r0 == 0) goto L19
            java.lang.Object r0 = kotlin.collections.CollectionsKt.firstOrNull(r0)
            java.lang.String r0 = (java.lang.String) r0
            goto L1a
        L19:
            r0 = r1
        L1a:
            androidx.compose.ui.semantics.k r2 = r8.d
            r3 = 1
            r4 = 0
            if (r0 != 0) goto L56
            androidx.compose.ui.semantics.u r0 = androidx.compose.ui.semantics.r.x
            java.util.LinkedHashMap r5 = r2.a
            java.lang.Object r0 = r5.get(r0)
            if (r0 != 0) goto L2b
            r0 = r1
        L2b:
            androidx.compose.ui.text.g r0 = (androidx.compose.ui.text.C0995g) r0
            androidx.compose.ui.semantics.u r5 = androidx.compose.ui.semantics.r.u
            java.util.LinkedHashMap r6 = r2.a
            java.lang.Object r5 = r6.get(r5)
            if (r5 != 0) goto L38
            r5 = r1
        L38:
            java.util.List r5 = (java.util.List) r5
            if (r5 == 0) goto L42
            java.lang.Object r1 = kotlin.collections.CollectionsKt.firstOrNull(r5)
            androidx.compose.ui.text.g r1 = (androidx.compose.ui.text.C0995g) r1
        L42:
            if (r0 != 0) goto L45
            r0 = r1
        L45:
            if (r0 != 0) goto L56
            java.lang.String r0 = r7.v(r8)
            if (r0 != 0) goto L56
            boolean r0 = u(r8)
            if (r0 == 0) goto L54
            goto L56
        L54:
            r0 = r4
            goto L57
        L56:
            r0 = r3
        L57:
            boolean r1 = androidx.compose.ui.platform.N.B(r8)
            if (r1 == 0) goto L6a
            boolean r1 = r2.b
            if (r1 != 0) goto L69
            boolean r8 = r8.m()
            if (r8 == 0) goto L6a
            if (r0 == 0) goto L6a
        L69:
            return r3
        L6a:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.F.y(androidx.compose.ui.semantics.o):boolean");
    }

    public final void z(androidx.compose.ui.node.E e) {
        if (this.w.add(e)) {
            this.x.o(Unit.a);
        }
    }
}
