package com.quizlet.quizletandroid.ui.usersettings.fragments;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.AbstractC1373j0;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.H6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.api.model.ProfileImage;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4617v;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.h;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import com.quizlet.quizletandroid.ui.usersettings.activities.CropImageActivity;
import dagger.hilt.android.internal.managers.j;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class ChangeProfileImageFragment extends Hilt_ChangeProfileImageFragment<C4617v> {
    public static final String w;
    public ProgressDialog p;
    public androidx.camera.camera2.internal.compat.workaround.e q;
    public androidx.camera.camera2.internal.concurrent.a r;
    public com.quizlet.quizletandroid.ui.common.images.capture.b s;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e t;
    public com.quizlet.quizletandroid.ui.usersettings.adapters.c u;
    public androidx.activity.result.b v;

    static {
        Intrinsics.checkNotNullExpressionValue("ChangeProfileImageFragment", "getSimpleName(...)");
        w = "ChangeProfileImageFragment";
    }

    public ChangeProfileImageFragment() {
        k kVarA = l.a(m.c, new t(new t(this, 3), 4));
        this.t = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.usersettings.viewmodels.c.class), new i(kVarA, 11), new h(this, kVarA, 27), new i(kVarA, 12));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return w;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_change_profile_image, viewGroup, false);
        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) viewInflate;
        RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.recycler_view, viewInflate);
        if (recyclerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.recycler_view)));
        }
        C4617v c4617v = new C4617v(coordinatorLayout, recyclerView);
        Intrinsics.checkNotNullExpressionValue(c4617v, "inflate(...)");
        return c4617v;
    }

    public final void U(Uri uri) throws Exception {
        Context context = getContext();
        com.quizlet.quizletandroid.ui.common.images.capture.b bVar = this.s;
        if (bVar == null) {
            Intrinsics.m("mProfileImageCache");
            throw null;
        }
        Uri uriFromFile = Uri.fromFile(bVar.a(context));
        int i = CropImageActivity.o;
        Intent intent = new Intent(context, (Class<?>) CropImageActivity.class);
        intent.putExtra("EXTRA_SOURCE_URI", uri);
        intent.putExtra("EXTRA_SAVE_URI", uriFromFile);
        startActivityForResult(intent, 1002);
    }

    public final void V(String str, String str2) {
        Intent intent = new Intent();
        intent.putExtra("EXTRA_PROFILE_IMAGE_ID", str);
        if (str2 != null) {
            intent.putExtra("EXTRA_PROFILE_IMAGE_URL", str2);
        }
        Fragment targetFragment = getTargetFragment();
        if (targetFragment != null) {
            targetFragment.onActivityResult(getTargetRequestCode(), -1, intent);
        } else {
            requireActivity().setResult(-1, intent);
            requireActivity().finish();
        }
    }

    public final androidx.camera.camera2.internal.concurrent.a W() {
        androidx.camera.camera2.internal.concurrent.a aVar = this.r;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("mImageCapturer");
        throw null;
    }

    public final RecyclerView X() {
        RecyclerView recyclerView = ((C4617v) J()).b;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "recyclerView");
        return recyclerView;
    }

    public final boolean Y() {
        if (!requireArguments().getBoolean("ARG_ALLOW_CUSTOM_IMAGES") || getContext() == null) {
            return false;
        }
        W();
        return getContext().getPackageManager().hasSystemFeature("android.hardware.camera.any");
    }

    public final void a0(boolean z) {
        ProgressDialog progressDialog;
        ProgressDialog progressDialog2;
        if (z) {
            if (!isAdded() || (progressDialog2 = this.p) == null) {
                return;
            }
            progressDialog2.show();
            return;
        }
        ProgressDialog progressDialog3 = this.p;
        if (progressDialog3 == null || !progressDialog3.isShowing() || (progressDialog = this.p) == null) {
            return;
        }
        progressDialog.dismiss();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 1002 && i2 == -1) {
            V(intent != null ? intent.getStringExtra("EXTRA_PROFILE_IMAGE_ID") : null, null);
        }
        androidx.camera.camera2.internal.concurrent.a aVarW = W();
        Context context = getContext();
        if (i == 1000 && i2 == -1) {
            if (i == 1000) {
                try {
                    context.revokeUriPermission((Uri) aVarW.f, 3);
                    Uri path = (Uri) aVarW.e;
                    Intrinsics.checkNotNullParameter(path, "path");
                    U(path);
                } finally {
                    aVarW.b = -1;
                    aVarW.e = null;
                    aVarW.f = null;
                }
            }
        }
    }

    @Override // com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeSettingsBaseFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.u = new com.quizlet.quizletandroid.ui.usersettings.adapters.c(this);
        if (bundle != null) {
            W().M(bundle);
        }
        ProgressDialog progressDialog = new ProgressDialog(getContext(), R.style.QuizletProgressDialog);
        progressDialog.setProgressStyle(0);
        progressDialog.setCancelable(true);
        progressDialog.setOnCancelListener(new com.facebook.internal.K(this, 6));
        this.p = progressDialog;
        androidx.activity.result.b bVarG = H6.g(this, new a(this, 0));
        Intrinsics.checkNotNullParameter(bVarG, "<set-?>");
        this.v = bVarG;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroy() {
        androidx.camera.camera2.internal.concurrent.a aVarW = W();
        ((com.quizlet.qutils.image.capture.a) aVarW.c).d(getContext());
        super.onDestroy();
    }

    @Override // androidx.fragment.app.Fragment
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getItemId() != R.id.menu_user_settings_confirm) {
            return super.onOptionsItemSelected(item);
        }
        com.quizlet.quizletandroid.ui.usersettings.adapters.c cVar = this.u;
        ProfileImage profileImageD = cVar != null ? cVar.d(cVar.d) : null;
        com.quizlet.quizletandroid.ui.usersettings.viewmodels.c cVar2 = (com.quizlet.quizletandroid.ui.usersettings.viewmodels.c) this.t.getValue();
        String id = profileImageD != null ? profileImageD.getId() : null;
        String url = profileImageD != null ? profileImageD.getUrl() : null;
        cVar2.getClass();
        E.A(p0.j(cVar2), null, null, new com.quizlet.quizletandroid.ui.usersettings.viewmodels.b(cVar2, id, url, null), 3);
        return true;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onRequestPermissionsResult(int i, String[] permissions, int[] grantResults) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        androidx.camera.camera2.internal.compat.workaround.e eVar = this.q;
        if (eVar == null) {
            Intrinsics.m("mPermissionsManager");
            throw null;
        }
        final int i2 = 0;
        Function0 function0 = new Function0(this) { // from class: com.quizlet.quizletandroid.ui.usersettings.fragments.b
            public final /* synthetic */ ChangeProfileImageFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ChangeProfileImageFragment changeProfileImageFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = ChangeProfileImageFragment.w;
                        changeProfileImageFragment.W().F(changeProfileImageFragment, true);
                        return Unit.a;
                    default:
                        String str2 = ChangeProfileImageFragment.w;
                        if (changeProfileImageFragment.q != null) {
                            androidx.camera.camera2.internal.compat.workaround.e.r(changeProfileImageFragment);
                            return Unit.a;
                        }
                        Intrinsics.m("mPermissionsManager");
                        throw null;
                }
            }
        };
        final int i3 = 1;
        androidx.camera.camera2.internal.compat.workaround.e.l(eVar, this, i, permissions, grantResults, function0, new Function0(this) { // from class: com.quizlet.quizletandroid.ui.usersettings.fragments.b
            public final /* synthetic */ ChangeProfileImageFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                ChangeProfileImageFragment changeProfileImageFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = ChangeProfileImageFragment.w;
                        changeProfileImageFragment.W().F(changeProfileImageFragment, true);
                        return Unit.a;
                    default:
                        String str2 = ChangeProfileImageFragment.w;
                        if (changeProfileImageFragment.q != null) {
                            androidx.camera.camera2.internal.compat.workaround.e.r(changeProfileImageFragment);
                            return Unit.a;
                        }
                        Intrinsics.m("mPermissionsManager");
                        throw null;
                }
            }
        });
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        W().N(outState);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        requireActivity().setTitle(R.string.profile_image_activity_title);
        com.quizlet.quizletandroid.ui.usersettings.adapters.c cVar = this.u;
        if (cVar == null || !cVar.b.isEmpty()) {
            return;
        }
        com.quizlet.quizletandroid.ui.usersettings.d dVar = this.f;
        io.reactivex.rxjava3.internal.operators.single.d dVar2 = new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.single.e(new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.mixed.b(4, dVar.d.getProfileImages().l(dVar.b).h(dVar.c).e(new com.quizlet.quizletandroid.ui.usersettings.b(dVar, 0)).e(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(16)), new com.quizlet.quizletandroid.ui.usersettings.b(dVar, 2)).l(new com.quizlet.quizletandroid.ui.usersettings.b(dVar, 1)).x(16), new c(this, 0), 1), new com.quizlet.eventlogger.e(this, 22), 0), new c(this, 1), 2);
        Intrinsics.checkNotNullExpressionValue(dVar2, "doOnSuccess(...)");
        this.j.b(B7.b(dVar2, new y(1, this, ChangeProfileImageFragment.class, "onImageLoadError", "onImageLoadError(Ljava/lang/Throwable;)V", 0, 19), new a(this, 1)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        C4617v c4617v = (C4617v) J();
        com.quizlet.quizletandroid.ui.setcreation.imageupload.a aVar = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(18);
        WeakHashMap weakHashMap = V.a;
        L.m(c4617v.b, aVar);
        ((com.quizlet.quizletandroid.ui.usersettings.viewmodels.c) this.t.getValue()).f.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.fragments.c(new a(this, 2)));
        X().setLayoutManager(new GridLayoutManager((j) getContext(), getResources().getInteger(R.integer.user_settings_change_profile_image_columns)));
        X().setAdapter(this.u);
        com.quizlet.baserecyclerview.decoration.c cVar = new com.quizlet.baserecyclerview.decoration.c(getContext(), 3, 0, com.quizlet.baserecyclerview.decoration.b.Z0);
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        cVar.a.setColor(com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.SysColorDivider));
        X().i(cVar);
        AbstractC1373j0 itemAnimator = X().getItemAnimator();
        if (itemAnimator != null) {
            itemAnimator.f = 0L;
        }
    }
}
