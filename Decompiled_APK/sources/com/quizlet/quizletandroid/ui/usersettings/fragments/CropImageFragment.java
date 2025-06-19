package com.quizlet.quizletandroid.ui.usersettings.fragments;

import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.lyft.android.scissors.CropView;
import com.quizlet.infra.legacysyncengine.net.request.g;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4618w;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.observers.h;
import io.reactivex.rxjava3.internal.operators.observable.B;
import io.reactivex.rxjava3.internal.operators.observable.C;
import io.reactivex.rxjava3.internal.operators.observable.W;
import io.reactivex.rxjava3.internal.operators.observable.m0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class CropImageFragment extends Hilt_CropImageFragment<C4618w> {
    public static final String s;
    public o p;
    public o q;
    public h r;

    static {
        Intrinsics.checkNotNullExpressionValue("CropImageFragment", "getSimpleName(...)");
        s = "CropImageFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return s;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_crop_image, viewGroup, false);
        if (viewInflate == null) {
            throw new NullPointerException("rootView");
        }
        CropView cropView = (CropView) viewInflate;
        C4618w c4618w = new C4618w(cropView, cropView);
        Intrinsics.checkNotNullExpressionValue(c4618w, "inflate(...)");
        return c4618w;
    }

    @Override // androidx.fragment.app.Fragment
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getItemId() != R.id.menu_user_settings_confirm) {
            return false;
        }
        Uri uri = (Uri) requireArguments().getParcelable("ARG_SAVE_URI");
        if (uri == null) {
            return true;
        }
        CropView cropImageView = ((C4618w) J()).b;
        Intrinsics.checkNotNullExpressionValue(cropImageView, "cropImageView");
        com.jakewharton.rxbinding4.a aVar = new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.classfolder.b(10, uri, cropImageView), 4);
        Intrinsics.checkNotNullExpressionValue(aVar, "defer(...)");
        i iVarM = aVar.m(new com.quizlet.local.ormlite.models.term.b(this, 13), SubsamplingScaleImageView.TILE_SIZE_AUTO);
        o oVar = this.p;
        if (oVar == null) {
            Intrinsics.m("mNetworkScheduler");
            throw null;
        }
        m0 m0VarW = iVarM.w(oVar);
        o oVar2 = this.q;
        if (oVar2 == null) {
            Intrinsics.m("mMainThreadScheduler");
            throw null;
        }
        W wS = m0VarW.s(oVar2);
        com.quizlet.quizletandroid.ui.setpage.terms.c cVar = new com.quizlet.quizletandroid.ui.setpage.terms.c(this, 9);
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        C c = new C(wS, cVar, bVar);
        com.quizlet.eventlogger.e eVar = new com.quizlet.eventlogger.e(this, 23);
        g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        B b = new B(c, gVar, gVar, bVar, eVar);
        Intrinsics.checkNotNullExpressionValue(b, "doAfterTerminate(...)");
        this.r = B7.d(b, new y(1, this, CropImageFragment.class, "onProfileImageUploadError", "onProfileImageUploadError(Ljava/lang/Throwable;)V", 0, 21), null, new y(1, this, CropImageFragment.class, "onProfileImageUploaded", "onProfileImageUploaded(Lcom/quizlet/api/model/ApiResponse;)V", 0, 20), 2);
        return true;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        requireActivity().setTitle(R.string.crop_image_activity_title);
    }

    @Override // com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeSettingsBaseFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        h hVar;
        super.onStop();
        h hVar2 = this.r;
        if (hVar2 == null || hVar2.c() || (hVar = this.r) == null) {
            return;
        }
        io.reactivex.rxjava3.internal.disposables.a.a(hVar);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        CropView cropImageView = ((C4618w) J()).b;
        Intrinsics.checkNotNullExpressionValue(cropImageView, "cropImageView");
        cropImageView.setViewportRatio(1.0f);
        CropView cropImageView2 = ((C4618w) J()).b;
        Intrinsics.checkNotNullExpressionValue(cropImageView2, "cropImageView");
        if (cropImageView2.g == null) {
            cropImageView2.g = new com.lyft.android.scissors.b(cropImageView2, 0);
        }
        cropImageView2.g.o((Uri) requireArguments().getParcelable("ARG_SOURCE_URI"));
        if (this.i) {
            return;
        }
        this.i = true;
        getActivity().invalidateOptionsMenu();
    }
}
