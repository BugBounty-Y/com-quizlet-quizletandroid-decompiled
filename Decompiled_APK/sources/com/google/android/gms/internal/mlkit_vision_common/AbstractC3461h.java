package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import androidx.compose.material3.A4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3461h;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.quizlet.assembly.compose.input.r;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okio.InterfaceC5093j;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3461h {
    public static final void a(final com.quizlet.features.questiontypes.written.ui.i uiState, androidx.compose.ui.n nVar, final Function2 function2, final kotlin.jvm.functions.c cVar, final com.quizlet.assembly.compose.input.r rVar, float f, final androidx.compose.material3.A4 a4, InterfaceC0806l interfaceC0806l, final int i) {
        int i2;
        androidx.compose.ui.n nVar2;
        float f2;
        InterfaceC0773a0 interfaceC0773a0;
        Object obj;
        androidx.compose.ui.n nVar3;
        int i3;
        InterfaceC0773a0 interfaceC0773a02;
        C0814p c0814p;
        InterfaceC0773a0 interfaceC0773a03;
        androidx.compose.ui.focus.p pVar;
        final androidx.compose.ui.n nVar4;
        final float f3;
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-769451415);
        int i4 = i | (c0814p2.h(uiState) ? 4 : 2) | 48 | (c0814p2.h(function2) ? 256 : 128) | (c0814p2.h(cVar) ? 2048 : 1024) | (c0814p2.h(rVar) ? 16384 : 8192) | 65536 | (c0814p2.f(a4) ? 1048576 : 524288);
        if ((599187 & i4) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            nVar4 = nVar;
            f3 = f;
        } else {
            c0814p2.S();
            int i5 = i & 1;
            Object obj2 = C0804k.a;
            if (i5 == 0 || c0814p2.w()) {
                androidx.compose.ui.n nVar5 = androidx.compose.ui.n.b;
                com.quizlet.themes.m.g.d();
                i2 = i4 & (-458753);
                nVar2 = nVar5;
                f2 = com.quizlet.ui.resources.designsystem.generated.f.g;
            } else {
                c0814p2.Q();
                f2 = f;
                i2 = i4 & (-458753);
                nVar2 = nVar;
            }
            c0814p2.q();
            c0814p2.X(-1125181866);
            Object objI = c0814p2.I();
            if (objI == obj2) {
                objI = new androidx.compose.ui.focus.p();
                c0814p2.i0(objI);
            }
            androidx.compose.ui.focus.p pVar2 = (androidx.compose.ui.focus.p) objI;
            c0814p2.p(false);
            Object[] objArr = new Object[0];
            c0814p2.X(-1125179687);
            boolean zH = c0814p2.h(uiState);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == obj2) {
                final int i6 = 0;
                objI2 = new Function0() { // from class: com.quizlet.features.questiontypes.written.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i6) {
                            case 0:
                                return C0776c.z(uiState.a);
                            case 1:
                                return C0776c.z(Boolean.valueOf(uiState.c));
                            case 2:
                                return C0776c.z(Boolean.valueOf(uiState.d));
                            default:
                                return C0776c.z(Boolean.valueOf(uiState.e));
                        }
                    }
                };
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a04 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, null, (Function0) objI2, c0814p2, 0, 6);
            Object[] objArr2 = new Object[0];
            c0814p2.X(-1125177311);
            boolean zH2 = c0814p2.h(uiState);
            Object objI3 = c0814p2.I();
            if (zH2 || objI3 == obj2) {
                objI3 = new C4392k(uiState, 22);
                c0814p2.i0(objI3);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a05 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr2, null, (Function0) objI3, c0814p2, 0, 6);
            Object[] objArr3 = new Object[0];
            c0814p2.X(-1125174786);
            boolean zH3 = c0814p2.h(uiState);
            Object objI4 = c0814p2.I();
            if (zH3 || objI4 == obj2) {
                final int i7 = 1;
                objI4 = new Function0() { // from class: com.quizlet.features.questiontypes.written.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i7) {
                            case 0:
                                return C0776c.z(uiState.a);
                            case 1:
                                return C0776c.z(Boolean.valueOf(uiState.c));
                            case 2:
                                return C0776c.z(Boolean.valueOf(uiState.d));
                            default:
                                return C0776c.z(Boolean.valueOf(uiState.e));
                        }
                    }
                };
                c0814p2.i0(objI4);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a06 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr3, null, (Function0) objI4, c0814p2, 0, 6);
            Object[] objArr4 = new Object[0];
            c0814p2.X(-1125172354);
            boolean zH4 = c0814p2.h(uiState);
            Object objI5 = c0814p2.I();
            if (zH4 || objI5 == obj2) {
                final int i8 = 2;
                objI5 = new Function0() { // from class: com.quizlet.features.questiontypes.written.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i8) {
                            case 0:
                                return C0776c.z(uiState.a);
                            case 1:
                                return C0776c.z(Boolean.valueOf(uiState.c));
                            case 2:
                                return C0776c.z(Boolean.valueOf(uiState.d));
                            default:
                                return C0776c.z(Boolean.valueOf(uiState.e));
                        }
                    }
                };
                c0814p2.i0(objI5);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a07 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr4, null, (Function0) objI5, c0814p2, 0, 6);
            Object[] objArr5 = new Object[0];
            c0814p2.X(-1125169856);
            boolean zH5 = c0814p2.h(uiState);
            Object objI6 = c0814p2.I();
            if (zH5 || objI6 == obj2) {
                final int i9 = 3;
                objI6 = new Function0() { // from class: com.quizlet.features.questiontypes.written.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i9) {
                            case 0:
                                return C0776c.z(uiState.a);
                            case 1:
                                return C0776c.z(Boolean.valueOf(uiState.c));
                            case 2:
                                return C0776c.z(Boolean.valueOf(uiState.d));
                            default:
                                return C0776c.z(Boolean.valueOf(uiState.e));
                        }
                    }
                };
                c0814p2.i0(objI6);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a08 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr5, null, (Function0) objI6, c0814p2, 0, 6);
            Object[] objArr6 = new Object[0];
            c0814p2.X(-1125167362);
            boolean zH6 = c0814p2.h(uiState);
            Object objI7 = c0814p2.I();
            if (zH6 || objI7 == obj2) {
                objI7 = new C4392k(uiState, 23);
                c0814p2.i0(objI7);
            }
            c0814p2.p(false);
            InterfaceC0773a0 interfaceC0773a09 = (InterfaceC0773a0) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr6, null, (Function0) objI7, c0814p2, 0, 6);
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            Object obj3 = uiState.g;
            if (obj3 != null && !obj3.equals(com.quizlet.features.questiontypes.written.ui.j.a)) {
                String str = (String) interfaceC0773a05.getValue();
                if (str == null || StringsKt.O(str) || StringsKt.O((String) interfaceC0773a04.getValue())) {
                    String str2 = (String) interfaceC0773a05.getValue();
                    if ((str2 == null || StringsKt.O(str2)) && !StringsKt.O((String) interfaceC0773a04.getValue())) {
                        obj3 = null;
                    }
                } else {
                    obj3 = com.quizlet.features.questiontypes.written.ui.m.b;
                }
            }
            j.a = obj3;
            c0814p2.X(-1125147889);
            boolean zF = c0814p2.f(interfaceC0773a04) | c0814p2.h(uiState) | c0814p2.f(interfaceC0773a06) | c0814p2.f(interfaceC0773a07) | c0814p2.f(interfaceC0773a08) | c0814p2.f(interfaceC0773a09) | c0814p2.f(interfaceC0773a05);
            androidx.compose.ui.n nVar6 = nVar2;
            Object objI8 = c0814p2.I();
            if (zF || objI8 == obj2) {
                interfaceC0773a0 = interfaceC0773a08;
                obj = obj2;
                nVar3 = nVar6;
                i3 = i2;
                interfaceC0773a02 = interfaceC0773a06;
                c0814p = c0814p2;
                interfaceC0773a03 = interfaceC0773a04;
                pVar = pVar2;
                objI8 = new com.quizlet.features.questiontypes.written.ui.d(uiState, pVar, interfaceC0773a03, interfaceC0773a02, interfaceC0773a07, interfaceC0773a0, interfaceC0773a09, interfaceC0773a05, null);
                c0814p.i0(objI8);
            } else {
                nVar3 = nVar6;
                i3 = i2;
                interfaceC0773a02 = interfaceC0773a06;
                interfaceC0773a0 = interfaceC0773a08;
                c0814p = c0814p2;
                obj = obj2;
                interfaceC0773a03 = interfaceC0773a04;
                pVar = pVar2;
            }
            c0814p.p(false);
            C0776c.f(c0814p, uiState, (Function2) objI8);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.U.b(nVar3, ((Boolean) interfaceC0773a0.getValue()).booleanValue(), 2), "writtenQuestionInput");
            String str3 = (String) interfaceC0773a03.getValue();
            String strA = uiState.b.a((Context) c0814p.j(AndroidCompositionLocals_androidKt.b));
            boolean zBooleanValue = ((Boolean) interfaceC0773a02.getValue()).booleanValue();
            boolean zBooleanValue2 = ((Boolean) interfaceC0773a09.getValue()).booleanValue();
            com.quizlet.features.questiontypes.written.ui.o oVar = (com.quizlet.features.questiontypes.written.ui.o) j.a;
            c0814p.X(-1125116346);
            com.quizlet.assembly.compose.input.w wVarA = oVar != null ? oVar.a(c0814p) : null;
            c0814p.p(false);
            c0814p.X(-1125130075);
            boolean zH7 = c0814p.h(uiState) | c0814p.f(interfaceC0773a03);
            Object objI9 = c0814p.I();
            if (zH7 || objI9 == obj) {
                objI9 = new androidx.lifecycle.u0(29, uiState, interfaceC0773a03);
                c0814p.i0(objI9);
            }
            Function1 function1 = (Function1) objI9;
            c0814p.p(false);
            c0814p.X(-1125122143);
            boolean zF2 = ((i3 & 896) == 256) | c0814p.f(interfaceC0773a03) | c0814p.f(interfaceC0773a07);
            Object objI10 = c0814p.I();
            if (zF2 || objI10 == obj) {
                objI10 = new com.quizlet.features.questiontypes.written.ui.c(function2, interfaceC0773a03, interfaceC0773a07, 0);
                c0814p.i0(objI10);
            }
            c0814p.p(false);
            C0814p c0814p3 = c0814p;
            AbstractC3745v5.b(str3, function1, qVarG, null, strA, 0, 0, pVar, 7, 0, (Function0) objI10, null, zBooleanValue, wVarA, new androidx.work.impl.utils.o(j, cVar, interfaceC0773a03, interfaceC0773a07, 7), zBooleanValue2, 0, rVar, f2, a4, null, c0814p3, 805306368, 6, (i3 >> 9) & 8176, 17926632);
            c0814p2 = c0814p3;
            nVar4 = nVar3;
            f3 = f2;
        }
        C0813o0 c0813o0R = c0814p2.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(nVar4, function2, cVar, rVar, f3, a4, i) { // from class: com.quizlet.features.questiontypes.written.ui.a
                public final /* synthetic */ androidx.compose.ui.n b;
                public final /* synthetic */ Function2 c;
                public final /* synthetic */ kotlin.jvm.functions.c d;
                public final /* synthetic */ r e;
                public final /* synthetic */ float f;
                public final /* synthetic */ A4 g;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj4, Object obj5) {
                    ((Integer) obj5).getClass();
                    int iH = C0776c.H(1);
                    i iVar = this.a;
                    r rVar2 = this.e;
                    A4 a42 = this.g;
                    AbstractC3461h.a(iVar, this.b, this.c, this.d, rVar2, this.f, a42, (InterfaceC0806l) obj4, iH);
                    return Unit.a;
                }
            };
        }
    }

    public static final coil3.network.t b(okhttp3.H h) {
        InterfaceC5093j interfaceC5093jF0;
        int i = h.d;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = h.f.iterator();
        while (true) {
            androidx.collection.Y y = (androidx.collection.Y) it2;
            if (!y.hasNext()) {
                break;
            }
            Pair pair = (Pair) y.next();
            String str = (String) pair.a;
            String str2 = (String) pair.b;
            String lowerCase = str.toLowerCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            Object arrayList = linkedHashMap.get(lowerCase);
            if (arrayList == null) {
                arrayList = new ArrayList();
                linkedHashMap.put(lowerCase, arrayList);
            }
            ((List) arrayList).add(str2);
        }
        coil3.network.r rVar = new coil3.network.r(kotlin.collections.V.l(linkedHashMap));
        okhttp3.J j = h.g;
        return new coil3.network.t(i, h.k, h.l, rVar, (j == null || (interfaceC5093jF0 = j.f0()) == null) ? null : new coil3.network.u(interfaceC5093jF0), h);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final okhttp3.C c(coil3.network.s r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r0 = 1
            boolean r1 = r7 instanceof coil3.network.okhttp.internal.e
            if (r1 == 0) goto L14
            r1 = r7
            coil3.network.okhttp.internal.e r1 = (coil3.network.okhttp.internal.e) r1
            int r2 = r1.k
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L14
            int r2 = r2 - r3
            r1.k = r2
            goto L19
        L14:
            coil3.network.okhttp.internal.e r1 = new coil3.network.okhttp.internal.e
            r1.<init>(r7)
        L19:
            java.lang.Object r7 = r1.j
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r1 = r1.k
            r2 = 0
            if (r1 == 0) goto L46
            if (r1 != r0) goto L3e
            androidx.glance.appwidget.protobuf.Z.e(r7)
            okio.k r7 = (okio.k) r7
            if (r7 == 0) goto L39
            java.lang.String r6 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r6)
            okhttp3.D r6 = new okhttp3.D
            r6.<init>(r2, r7, r0)
            r7 = r2
            r0 = r7
            r1 = r0
            goto L5d
        L39:
            r6 = r2
            r7 = r6
            r0 = r7
            r1 = r0
            goto L59
        L3e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L46:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.remote.model.notes.e r7 = new com.quizlet.remote.model.notes.e
            r0 = 13
            r7.<init>(r0)
            java.lang.String r0 = r6.a
            r7.r(r0)
            java.lang.String r0 = r6.b
            r1 = r0
            r0 = r7
        L59:
            r5 = r7
            r7 = r6
            r6 = r2
            r2 = r5
        L5d:
            r2.n(r1, r6)
            coil3.network.r r6 = r7.c
            com.android.billingclient.api.h r7 = new com.android.billingclient.api.h
            r1 = 3
            r7.<init>(r1)
            java.util.Map r6 = r6.a
            java.util.Set r6 = r6.entrySet()
            java.util.Iterator r6 = r6.iterator()
        L72:
            boolean r1 = r6.hasNext()
            if (r1 == 0) goto L9e
            java.lang.Object r1 = r6.next()
            java.util.Map$Entry r1 = (java.util.Map.Entry) r1
            java.lang.Object r2 = r1.getKey()
            java.lang.String r2 = (java.lang.String) r2
            java.lang.Object r1 = r1.getValue()
            java.util.List r1 = (java.util.List) r1
            java.util.Iterator r1 = r1.iterator()
        L8e:
            boolean r3 = r1.hasNext()
            if (r3 == 0) goto L72
            java.lang.Object r3 = r1.next()
            java.lang.String r3 = (java.lang.String) r3
            r7.c(r2, r3)
            goto L8e
        L9e:
            okhttp3.r r6 = r7.d()
            r0.getClass()
            java.lang.String r7 = "headers"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r7)
            com.android.billingclient.api.h r6 = r6.e()
            r0.d = r6
            okhttp3.C r6 = r0.i()
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3461h.c(coil3.network.s, kotlin.coroutines.jvm.internal.c):okhttp3.C");
    }
}
