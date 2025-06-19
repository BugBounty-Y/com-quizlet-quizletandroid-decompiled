package com.quizlet.features.notes.detail.navigation;

import android.os.Bundle;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.navigation.C1291m;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3435c3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3501n3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3507o3;
import com.google.android.gms.internal.mlkit_vision_common.T2;
import com.google.android.gms.internal.mlkit_vision_common.U2;
import com.google.android.gms.internal.mlkit_vision_common.W2;
import com.google.android.gms.internal.mlkit_vision_common.X2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.quizlet.features.settings.composables.x;
import com.quizlet.features.settings.viewmodels.C4446d;
import com.quizlet.features.settings.viewmodels.C4451i;
import com.quizlet.features.settings.viewmodels.q;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ H b;

    public /* synthetic */ d(H h, int i) {
        this.a = i;
        this.b = h;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        String string;
        String string2;
        switch (this.a) {
            case 0:
                C1291m it2 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it2, "it");
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(-1209993318);
                H h = this.b;
                boolean zH = c0814p.h(h);
                Object objI = c0814p.I();
                if (zH || objI == C0804k.a) {
                    objI = new com.quizlet.features.flashcards.navigation.c(0, h, H.class, "navigateUp", "navigateUp()Z", 8, 1);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                AbstractC3171i7.b((Function0) objI, null, c0814p, 0);
                return Unit.a;
            case 1:
                C1291m it3 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it3, "it");
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(-1209987681);
                H h2 = this.b;
                boolean zH2 = c0814p2.h(h2);
                Object objI2 = c0814p2.I();
                if (zH2 || objI2 == C0804k.a) {
                    objI2 = new e(h2, 0);
                    c0814p2.i0(objI2);
                }
                c0814p2.p(false);
                AbstractC3119d0.d((Function1) objI2, null, c0814p2, 0);
                return Unit.a;
            case 2:
                C1291m it4 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it4, "it");
                com.quizlet.features.settings.data.models.h hVar = com.quizlet.features.settings.data.models.h.b;
                C0814p c0814p3 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p3.Y(1890788296);
                C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p3);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p3);
                c0814p3.Y(1729797275);
                Object objE = AbstractC3417z1.e(C4451i.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p3);
                c0814p3.p(false);
                c0814p3.p(false);
                q qVar = (q) objE;
                c0814p3.X(-135357825);
                H h3 = this.b;
                boolean zH3 = c0814p3.h(h3);
                Object objI3 = c0814p3.I();
                if (zH3 || objI3 == C0804k.a) {
                    com.quizlet.features.flashcards.navigation.c cVar = new com.quizlet.features.flashcards.navigation.c(0, h3, H.class, "navigateUp", "navigateUp()Z", 8, 10);
                    c0814p3.i0(cVar);
                    objI3 = cVar;
                }
                c0814p3.p(false);
                AbstractC3501n3.b(hVar, qVar, (Function0) objI3, c0814p3, 6);
                return Unit.a;
            case 3:
                C1291m it5 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it5, "it");
                C0814p c0814p4 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p4.X(-135436225);
                H h4 = this.b;
                boolean zH4 = c0814p4.h(h4);
                Object objI4 = c0814p4.I();
                if (zH4 || objI4 == C0804k.a) {
                    objI4 = new com.quizlet.features.flashcards.navigation.c(0, h4, H.class, "navigateUp", "navigateUp()Z", 8, 11);
                    c0814p4.i0(objI4);
                }
                c0814p4.p(false);
                X2.a(null, (Function0) objI4, c0814p4, 0);
                return Unit.a;
            case 4:
                C1291m it6 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it6, "it");
                C0814p c0814p5 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p5.X(-135430369);
                H h5 = this.b;
                boolean zH5 = c0814p5.h(h5);
                Object objI5 = c0814p5.I();
                if (zH5 || objI5 == C0804k.a) {
                    objI5 = new com.quizlet.features.flashcards.navigation.c(0, h5, H.class, "navigateUp", "navigateUp()Z", 8, 12);
                    c0814p5.i0(objI5);
                }
                c0814p5.p(false);
                W2.a(null, (Function0) objI5, c0814p5, 0);
                return Unit.a;
            case 5:
                C1291m it7 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it7, "it");
                C0814p c0814p6 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p6.X(-135417921);
                H h6 = this.b;
                boolean zH6 = c0814p6.h(h6);
                Object objI6 = c0814p6.I();
                V v = C0804k.a;
                if (zH6 || objI6 == v) {
                    objI6 = new com.quizlet.features.flashcards.navigation.c(0, h6, H.class, "navigateUp", "navigateUp()Z", 8, 13);
                    c0814p6.i0(objI6);
                }
                Function0 function0 = (Function0) objI6;
                c0814p6.p(false);
                c0814p6.X(-135424460);
                final H h7 = this.b;
                boolean zH7 = c0814p6.h(h7);
                Object objI7 = c0814p6.I();
                if (zH7 || objI7 == v) {
                    final int i = 0;
                    objI7 = new Function0() { // from class: com.quizlet.features.settings.composables.navigation.b
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i) {
                                case 0:
                                    H h8 = h7;
                                    h8.e();
                                    androidx.navigation.r.d(h8, "updateEmailConfirmationDialog");
                                    break;
                                default:
                                    H h9 = h7;
                                    h9.e();
                                    androidx.navigation.r.d(h9, "updateEmailConfirmationDialog");
                                    break;
                            }
                            return Unit.a;
                        }
                    };
                    c0814p6.i0(objI7);
                }
                c0814p6.p(false);
                U2.a(0, c0814p6, null, function0, (Function0) objI7);
                return Unit.a;
            case 6:
                C1291m it8 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it8, "it");
                C0814p c0814p7 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p7.X(-135411916);
                final H h8 = this.b;
                boolean zH8 = c0814p7.h(h8);
                Object objI8 = c0814p7.I();
                V v2 = C0804k.a;
                if (zH8 || objI8 == v2) {
                    final int i2 = 1;
                    objI8 = new Function0() { // from class: com.quizlet.features.settings.composables.navigation.b
                        @Override // kotlin.jvm.functions.Function0
                        public final Object invoke() {
                            switch (i2) {
                                case 0:
                                    H h82 = h8;
                                    h82.e();
                                    androidx.navigation.r.d(h82, "updateEmailConfirmationDialog");
                                    break;
                                default:
                                    H h9 = h8;
                                    h9.e();
                                    androidx.navigation.r.d(h9, "updateEmailConfirmationDialog");
                                    break;
                            }
                            return Unit.a;
                        }
                    };
                    c0814p7.i0(objI8);
                }
                Function0 function02 = (Function0) objI8;
                c0814p7.p(false);
                c0814p7.X(-135405377);
                H h9 = this.b;
                boolean zH9 = c0814p7.h(h9);
                Object objI9 = c0814p7.I();
                if (zH9 || objI9 == v2) {
                    objI9 = new com.quizlet.features.flashcards.navigation.c(0, h9, H.class, "navigateUp", "navigateUp()Z", 8, 14);
                    c0814p7.i0(objI9);
                }
                c0814p7.p(false);
                T2.a(0, c0814p7, null, function02, (Function0) objI9);
                return Unit.a;
            case 7:
                C1291m it9 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it9, "it");
                C0814p c0814p8 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p8.X(-135399073);
                H h10 = this.b;
                boolean zH10 = c0814p8.h(h10);
                Object objI10 = c0814p8.I();
                if (zH10 || objI10 == C0804k.a) {
                    objI10 = new com.quizlet.features.flashcards.navigation.c(0, h10, H.class, "navigateUp", "navigateUp()Z", 8, 15);
                    c0814p8.i0(objI10);
                }
                c0814p8.p(false);
                AbstractC3435c3.b((Function0) objI10, c0814p8, 0);
                return Unit.a;
            case 8:
                C1291m it10 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it10, "it");
                com.quizlet.features.settings.data.models.h hVar2 = com.quizlet.features.settings.data.models.h.a;
                C0814p c0814p9 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p9.Y(1890788296);
                C0 c0A2 = androidx.lifecycle.viewmodel.compose.a.a(c0814p9);
                if (c0A2 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC2 = AbstractC3405w1.c(c0A2, c0814p9);
                c0814p9.Y(1729797275);
                Object objE2 = AbstractC3417z1.e(C4446d.class, c0A2, null, fVarC2, c0A2 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A2).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p9);
                c0814p9.p(false);
                c0814p9.p(false);
                q qVar2 = (q) objE2;
                c0814p9.X(-135388833);
                H h11 = this.b;
                boolean zH11 = c0814p9.h(h11);
                Object objI11 = c0814p9.I();
                if (zH11 || objI11 == C0804k.a) {
                    com.quizlet.features.flashcards.navigation.c cVar2 = new com.quizlet.features.flashcards.navigation.c(0, h11, H.class, "navigateUp", "navigateUp()Z", 8, 16);
                    c0814p9.i0(cVar2);
                    objI11 = cVar2;
                }
                c0814p9.p(false);
                AbstractC3507o3.c(hVar2, qVar2, (Function0) objI11, c0814p9, 6);
                return Unit.a;
            case 9:
                C1291m it11 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it11, "it");
                com.quizlet.features.settings.data.models.h hVar3 = com.quizlet.features.settings.data.models.h.a;
                C0814p c0814p10 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p10.Y(1890788296);
                C0 c0A3 = androidx.lifecycle.viewmodel.compose.a.a(c0814p10);
                if (c0A3 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC3 = AbstractC3405w1.c(c0A3, c0814p10);
                c0814p10.Y(1729797275);
                Object objE3 = AbstractC3417z1.e(C4446d.class, c0A3, null, fVarC3, c0A3 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A3).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p10);
                c0814p10.p(false);
                c0814p10.p(false);
                q qVar3 = (q) objE3;
                c0814p10.X(-135378465);
                H h12 = this.b;
                boolean zH12 = c0814p10.h(h12);
                Object objI12 = c0814p10.I();
                if (zH12 || objI12 == C0804k.a) {
                    com.quizlet.features.flashcards.navigation.c cVar3 = new com.quizlet.features.flashcards.navigation.c(0, h12, H.class, "navigateUp", "navigateUp()Z", 8, 17);
                    c0814p10.i0(cVar3);
                    objI12 = cVar3;
                }
                c0814p10.p(false);
                AbstractC3501n3.b(hVar3, qVar3, (Function0) objI12, c0814p10, 6);
                return Unit.a;
            case 10:
                C1291m it12 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it12, "it");
                com.quizlet.features.settings.data.models.h hVar4 = com.quizlet.features.settings.data.models.h.b;
                C0814p c0814p11 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p11.Y(1890788296);
                C0 c0A4 = androidx.lifecycle.viewmodel.compose.a.a(c0814p11);
                if (c0A4 == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC4 = AbstractC3405w1.c(c0A4, c0814p11);
                c0814p11.Y(1729797275);
                Object objE4 = AbstractC3417z1.e(C4451i.class, c0A4, null, fVarC4, c0A4 instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A4).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p11);
                c0814p11.p(false);
                c0814p11.p(false);
                q qVar4 = (q) objE4;
                c0814p11.X(-135368193);
                H h13 = this.b;
                boolean zH13 = c0814p11.h(h13);
                Object objI13 = c0814p11.I();
                if (zH13 || objI13 == C0804k.a) {
                    com.quizlet.features.flashcards.navigation.c cVar4 = new com.quizlet.features.flashcards.navigation.c(0, h13, H.class, "navigateUp", "navigateUp()Z", 8, 18);
                    c0814p11.i0(cVar4);
                    objI13 = cVar4;
                }
                c0814p11.p(false);
                AbstractC3507o3.c(hVar4, qVar4, (Function0) objI13, c0814p11, 6);
                return Unit.a;
            case 11:
                C1291m it13 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it13, "it");
                C0814p c0814p12 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p12.X(1150328553);
                H h14 = this.b;
                boolean zH14 = c0814p12.h(h14);
                Object objI14 = c0814p12.I();
                V v3 = C0804k.a;
                if (zH14 || objI14 == v3) {
                    objI14 = new com.quizlet.features.flashcards.navigation.c(0, h14, H.class, "navigateUp", "navigateUp()Z", 8, 22);
                    c0814p12.i0(objI14);
                }
                Function0 function03 = (Function0) objI14;
                c0814p12.p(false);
                c0814p12.X(1150330706);
                H h15 = this.b;
                boolean zH15 = c0814p12.h(h15);
                Object objI15 = c0814p12.I();
                if (zH15 || objI15 == v3) {
                    x xVar = new x(1, h15, com.quizlet.login.common.navigation.e.class, "navigateToEmailSent", "navigateToEmailSent(Landroidx/navigation/NavHostController;Ljava/lang/String;)V", 1, 29);
                    c0814p12.i0(xVar);
                    objI15 = xVar;
                }
                c0814p12.p(false);
                AbstractC3621g0.c(function03, (Function1) ((kotlin.reflect.f) objI15), null, c0814p12, 0);
                return Unit.a;
            case 12:
                C1291m it14 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it14, "it");
                C0814p c0814p13 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p13.X(1150360361);
                H h16 = this.b;
                boolean zH16 = c0814p13.h(h16);
                Object objI16 = c0814p13.I();
                V v4 = C0804k.a;
                if (zH16 || objI16 == v4) {
                    objI16 = new com.quizlet.features.flashcards.navigation.c(0, h16, H.class, "navigateUp", "navigateUp()Z", 8, 24);
                    c0814p13.i0(objI16);
                }
                Function0 function04 = (Function0) objI16;
                c0814p13.p(false);
                c0814p13.X(1150362514);
                H h17 = this.b;
                boolean zH17 = c0814p13.h(h17);
                Object objI17 = c0814p13.I();
                if (zH17 || objI17 == v4) {
                    com.quizlet.login.common.navigation.d dVar = new com.quizlet.login.common.navigation.d(1, h17, com.quizlet.login.common.navigation.e.class, "navigateToEmailSent", "navigateToEmailSent(Landroidx/navigation/NavHostController;Ljava/lang/String;)V", 1, 3);
                    c0814p13.i0(dVar);
                    objI17 = dVar;
                }
                c0814p13.p(false);
                T.b(function04, (Function1) ((kotlin.reflect.f) objI17), null, c0814p13, 0);
                return Unit.a;
            case 13:
                C1291m it15 = (C1291m) obj;
                InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it15, "it");
                Bundle bundleA = it15.h.a();
                if (bundleA == null || (string = bundleA.getString("email")) == null) {
                    throw new IllegalArgumentException("E-mail is required");
                }
                C0814p c0814p14 = (C0814p) interfaceC0806l;
                c0814p14.X(1150373801);
                H h18 = this.b;
                boolean zH18 = c0814p14.h(h18);
                Object objI18 = c0814p14.I();
                if (zH18 || objI18 == C0804k.a) {
                    objI18 = new com.quizlet.features.flashcards.navigation.c(0, h18, H.class, "navigateUp", "navigateUp()Z", 8, 25);
                    c0814p14.i0(objI18);
                }
                c0814p14.p(false);
                K.b(0, c0814p14, null, string, (Function0) objI18);
                return Unit.a;
            default:
                C1291m it16 = (C1291m) obj;
                InterfaceC0806l interfaceC0806l2 = (InterfaceC0806l) obj2;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it16, "it");
                Bundle bundleA2 = it16.h.a();
                if (bundleA2 == null || (string2 = bundleA2.getString("email")) == null) {
                    throw new IllegalArgumentException("E-mail is required");
                }
                C0814p c0814p15 = (C0814p) interfaceC0806l2;
                c0814p15.X(1150407026);
                H h19 = this.b;
                boolean zH19 = c0814p15.h(h19);
                Object objI19 = c0814p15.I();
                V v5 = C0804k.a;
                if (zH19 || objI19 == v5) {
                    com.quizlet.login.common.navigation.d dVar2 = new com.quizlet.login.common.navigation.d(1, h19, com.quizlet.login.common.navigation.e.class, "navigateToEmailSent", "navigateToEmailSent(Landroidx/navigation/NavHostController;Ljava/lang/String;)V", 1, 6);
                    c0814p15.i0(dVar2);
                    objI19 = dVar2;
                }
                c0814p15.p(false);
                Function1 function1 = (Function1) ((kotlin.reflect.f) objI19);
                c0814p15.X(1150409067);
                H h20 = this.b;
                boolean zH20 = c0814p15.h(h20);
                Object objI20 = c0814p15.I();
                if (zH20 || objI20 == v5) {
                    com.quizlet.features.flashcards.navigation.c cVar5 = new com.quizlet.features.flashcards.navigation.c(0, h20, H.class, "popBackStack", "popBackStack()Z", 8, 27);
                    c0814p15.i0(cVar5);
                    objI20 = cVar5;
                }
                c0814p15.p(false);
                com.google.android.gms.internal.mlkit_vision_document_scanner.H.b(string2, function1, (Function0) objI20, null, null, c0814p15, 0);
                return Unit.a;
        }
    }
}
