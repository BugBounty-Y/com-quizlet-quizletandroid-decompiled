package com.quizlet.features.infra.folder.create;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.features.flashcards.C4242p;
import com.quizlet.features.infra.folder.create.data.g;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.reflect.f;

@Metadata
/* loaded from: classes3.dex */
public final class CreateFolderModalFragment extends Hilt_CreateFolderModalFragment {
    public static final String w;
    public final e v;

    static {
        Intrinsics.checkNotNullExpressionValue("CreateFolderModalFragment", "getSimpleName(...)");
        w = "CreateFolderModalFragment";
    }

    public CreateFolderModalFragment() {
        k kVarA = l.a(m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 25), 26));
        this.v = new e(K.a(com.quizlet.features.infra.folder.create.viewmodel.b.class), new C4062f(kVarA, 27), new androidx.credentials.playservices.controllers.BeginSignIn.d(25, this, kVarA), new C4062f(kVarA, 28));
    }

    public final void Q(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2014371301);
        if ((((c0814p2.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            x xVarH = Y5.h(true, true, c0814p2, 54, 4);
            com.quizlet.features.infra.folder.create.data.b bVar = com.quizlet.features.infra.folder.create.data.b.a;
            c0814p2.X(-1227297944);
            boolean zH = c0814p2.h(this);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (zH || objI == v) {
                objI = new b(this, 0);
                c0814p2.i0(objI);
            }
            kotlin.jvm.functions.d dVar = (kotlin.jvm.functions.d) objI;
            c0814p2.p(false);
            c0814p2.X(-1227291857);
            boolean zH2 = c0814p2.h(this);
            Object objI2 = c0814p2.I();
            if (zH2 || objI2 == v) {
                C4242p c4242p = new C4242p(0, this, CreateFolderModalFragment.class, "dismiss", "dismiss()V", 0, 20);
                c0814p2.i0(c4242p);
                objI2 = c4242p;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            L5.e(xVarH, "", null, null, bVar, null, false, false, null, null, dVar, (Function0) ((f) objI2), null, c0814p, 24632, 5100);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new a(this, i, 1);
        }
    }

    public final void R(InterfaceC0806l interfaceC0806l, int i) {
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(202804458);
        int i2 = (c0814p.h(this) ? 4 : 2) | i;
        if ((i2 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            g gVar = (g) C0776c.m(((com.quizlet.features.infra.folder.create.viewmodel.b) this.v.getValue()).d, c0814p).getValue();
            boolean z2 = gVar instanceof com.quizlet.features.infra.folder.create.data.d;
            V v = C0804k.a;
            if (z2) {
                c0814p.X(816073834);
                String strD = AbstractC3106b5.d(c0814p, R.string.client_error_net_exception);
                c0814p.X(816078300);
                boolean zH = c0814p.h(this);
                Object objI = c0814p.I();
                if (zH || objI == v) {
                    C4242p c4242p = new C4242p(0, this, CreateFolderModalFragment.class, "dismiss", "dismiss()V", 0, 21);
                    c0814p.i0(c4242p);
                    objI = c4242p;
                }
                c0814p.p(false);
                Function0 function0 = (Function0) ((f) objI);
                c0814p.X(816079772);
                boolean zH2 = c0814p.h(this);
                Object objI2 = c0814p.I();
                if (zH2 || objI2 == v) {
                    C4242p c4242p2 = new C4242p(0, this, CreateFolderModalFragment.class, "dismiss", "dismiss()V", 0, 22);
                    c0814p.i0(c4242p2);
                    objI2 = c4242p2;
                }
                c0814p.p(false);
                P5.a(strD, null, null, null, null, function0, null, null, (Function0) ((f) objI2), null, c0814p, 0, 734);
                c0814p = c0814p;
                c0814p.p(false);
            } else if (Intrinsics.b(gVar, com.quizlet.features.infra.folder.create.data.e.a)) {
                c0814p.X(816081210);
                Q(c0814p, i2 & 14);
                c0814p.p(false);
            } else if (gVar instanceof com.quizlet.features.infra.folder.create.data.f) {
                c0814p.X(-471245623);
                c0814p.p(false);
                getParentFragmentManager().g0(AbstractC3206m6.a(new Pair("createFolderResultArgFolderId", Long.valueOf(((com.quizlet.features.infra.folder.create.data.f) gVar).a.a()))), "createFolderRequestKey");
                if (!isStateSaved()) {
                    H(false, false);
                }
            } else {
                if (!(gVar instanceof com.quizlet.features.infra.folder.create.data.c)) {
                    throw Z.j(816072845, c0814p, false);
                }
                c0814p.X(-471010612);
                String strD2 = AbstractC3106b5.d(c0814p, R.string.create_folder_offline_info_dialog_title);
                String strD3 = AbstractC3106b5.d(c0814p, R.string.create_folder_offline_info_dialog_description);
                String strD4 = AbstractC3106b5.d(c0814p, R.string.got_it);
                c0814p.X(816101788);
                boolean zH3 = c0814p.h(this);
                Object objI3 = c0814p.I();
                if (zH3 || objI3 == v) {
                    z = false;
                    C4242p c4242p3 = new C4242p(0, this, CreateFolderModalFragment.class, "dismiss", "dismiss()V", 0, 23);
                    c0814p.i0(c4242p3);
                    objI3 = c4242p3;
                } else {
                    z = false;
                }
                c0814p.p(z);
                P5.a(strD3, null, strD2, null, strD4, null, null, null, (Function0) ((f) objI3), null, c0814p, 0, 746);
                c0814p = c0814p;
                c0814p.p(z);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new a(this, i, 0);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return AbstractC3162h7.b(this, new androidx.compose.runtime.internal.d(true, 1259831294, new c(this, 1)));
    }
}
