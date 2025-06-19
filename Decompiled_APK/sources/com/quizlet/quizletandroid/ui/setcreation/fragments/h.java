package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.os.Parcelable;
import androidx.camera.camera2.internal.C0128e;
import com.quizlet.quizletandroid.ui.setcreation.managers.CardFocusPosition;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ EditSetFragment b;

    public /* synthetic */ h(EditSetFragment editSetFragment, int i) {
        this.a = i;
        this.b = editSetFragment;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) throws Exception {
        EditSetFragment$initView$1 editSetFragment$initView$1;
        EditSetFragment editSetFragment = this.b;
        switch (this.a) {
            case 0:
                Boolean canUpsell = (Boolean) obj;
                Intrinsics.checkNotNullParameter(canUpsell, "canUpsell");
                if (!canUpsell.booleanValue()) {
                    String str = EditSetFragment.J;
                    editSetFragment.e0();
                    break;
                } else {
                    EditSetFragment.T(editSetFragment, com.quizlet.features.infra.models.upgrade.a.l);
                    break;
                }
            case 1:
                io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                editSetFragment.G(p0);
                break;
            case 2:
                CardFocusPosition focusDetails = (CardFocusPosition) obj;
                Intrinsics.checkNotNullParameter(focusDetails, "focusDetails");
                editSetFragment.G = focusDetails;
                editSetFragment.h0();
                break;
            case 3:
                io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                editSetFragment.G(p02);
                break;
            case 4:
                com.quizlet.qutils.android.a keyboardState = (com.quizlet.qutils.android.a) obj;
                Intrinsics.checkNotNullParameter(keyboardState, "keyboardState");
                String str2 = EditSetFragment.J;
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.e eVarC0 = editSetFragment.c0();
                eVarC0.getClass();
                Intrinsics.checkNotNullParameter(keyboardState, "keyboardState");
                eVarC0.k.j(keyboardState);
                break;
            case 5:
                io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                editSetFragment.I(p03);
                break;
            case 6:
                io.reactivex.rxjava3.disposables.b p04 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                editSetFragment.I(p04);
                break;
            default:
                List terms = (List) obj;
                Intrinsics.checkNotNullParameter(terms, "terms");
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.A;
                if (fVar != null) {
                    fVar.p = new ArrayList(terms);
                    fVar.notifyDataSetChanged();
                }
                editSetFragment.h0();
                C0128e c0128e = editSetFragment.H;
                if (c0128e != null) {
                    c0128e.accept(terms);
                }
                editSetFragment.H = null;
                Parcelable parcelable = editSetFragment.z;
                if (parcelable != null && (editSetFragment$initView$1 = editSetFragment.y) != null) {
                    editSetFragment$initView$1.j0(parcelable);
                    break;
                }
                break;
        }
    }
}
