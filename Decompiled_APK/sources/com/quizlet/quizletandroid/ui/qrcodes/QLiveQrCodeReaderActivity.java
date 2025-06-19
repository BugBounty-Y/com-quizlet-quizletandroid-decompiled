package com.quizlet.quizletandroid.ui.qrcodes;

import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraManager;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.camera.view.PreviewView;
import androidx.compose.animation.d0;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.app.AbstractC1016c;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.e0;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.uicommon.ui.common.dialogs.e;
import java.io.IOException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class QLiveQrCodeReaderActivity extends com.quizlet.ads.ui.activity.d implements e {
    public static final String t;
    public com.google.mlkit.vision.camera.a q;
    public s r;
    public GoogleApiAvailability s;

    static {
        Intrinsics.checkNotNullExpressionValue("QLiveQrCodeReaderActivity", "getSimpleName(...)");
        t = "QLiveQrCodeReaderActivity";
    }

    public QLiveQrCodeReaderActivity() {
        super(5);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return t;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        Toolbar toolbar = ((e0) K()).e;
        Intrinsics.checkNotNullExpressionValue(toolbar, "toolbar");
        return toolbar;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.qlive_qrcode_reader_activity, (ViewGroup) null, false);
        int i = R.id.bottomLeft;
        if (((ImageView) AbstractC3375o2.c(R.id.bottomLeft, viewInflate)) != null) {
            i = R.id.bottomRight;
            if (((ImageView) AbstractC3375o2.c(R.id.bottomRight, viewInflate)) != null) {
                i = R.id.cameraSourceView;
                PreviewView previewView = (PreviewView) AbstractC3375o2.c(R.id.cameraSourceView, viewInflate);
                if (previewView != null) {
                    i = R.id.enterGameCode;
                    QButton qButton = (QButton) AbstractC3375o2.c(R.id.enterGameCode, viewInflate);
                    if (qButton != null) {
                        i = R.id.header;
                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.header, viewInflate);
                        if (qTextView != null) {
                            i = R.id.toolbar;
                            Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, viewInflate);
                            if (toolbar != null) {
                                i = R.id.topLeft;
                                if (((ImageView) AbstractC3375o2.c(R.id.topLeft, viewInflate)) != null) {
                                    i = R.id.topRight;
                                    if (((ImageView) AbstractC3375o2.c(R.id.topRight, viewInflate)) != null) {
                                        e0 e0Var = new e0((ConstraintLayout) viewInflate, previewView, qButton, qTextView, toolbar);
                                        Intrinsics.checkNotNullExpressionValue(e0Var, "inflate(...)");
                                        return e0Var;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void b0() {
        int iA = androidx.core.content.c.a(this, "android.permission.CAMERA");
        s sVarC0 = c0();
        if (iA == 0) {
            QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = (QLiveQrCodeReaderActivity) sVarC0.h;
            if (qLiveQrCodeReaderActivity == null) {
                Intrinsics.m("view");
                throw null;
            }
            String[] permissions = (String[]) sVarC0.a;
            Intrinsics.checkNotNullParameter(permissions, "permissions");
            AbstractC1016c.g(qLiveQrCodeReaderActivity, permissions, 1);
            return;
        }
        QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity2 = (QLiveQrCodeReaderActivity) sVarC0.h;
        if (qLiveQrCodeReaderActivity2 == null) {
            Intrinsics.m("view");
            throw null;
        }
        e.a aVar = new e.a(qLiveQrCodeReaderActivity2);
        aVar.f(R.string.enable_camera_title);
        aVar.c(R.string.enable_camera_message);
        aVar.e(R.string.OK, new b(qLiveQrCodeReaderActivity2, 2));
        aVar.d(R.string.cancel, new b(qLiveQrCodeReaderActivity2, 3));
        aVar.g();
    }

    public final s c0() {
        s sVar = this.r;
        if (sVar != null) {
            return sVar;
        }
        Intrinsics.m("presenter");
        throw null;
    }

    public final void d0() {
        int i = QuizletLiveActivity.z;
        startActivity(AbstractC3721s5.b(this));
        finish();
    }

    public final void e0() {
        int i = 0;
        GoogleApiAvailability googleApiAvailability = this.s;
        if (googleApiAvailability == null) {
            Intrinsics.m("googleApiAvailability");
            throw null;
        }
        if (googleApiAvailability.c(getApplicationContext(), com.google.android.gms.common.c.a) != 0) {
            d0();
            return;
        }
        try {
            com.google.mlkit.vision.camera.a aVar = this.q;
            if (aVar != null) {
                aVar.b();
                Unit unit = Unit.a;
            }
        } catch (CameraUnavailableException e) {
            timber.log.c.a.e(e);
            e.a aVar2 = new e.a(this);
            aVar2.f(R.string.unable_open_camera);
            aVar2.c(R.string.quizlet_camera_error);
            aVar2.e(R.string.got_it, new b(this, i));
            aVar2.g();
            Unit unit2 = Unit.a;
        } catch (IOException e2) {
            timber.log.c.a.f(e2, "Could not start camera source.", new Object[0]);
            com.google.mlkit.vision.camera.a aVar3 = this.q;
            if (aVar3 != null) {
                aVar3.a();
            }
            this.q = null;
            Unit unit3 = Unit.a;
        } catch (SecurityException e3) {
            timber.log.c.a.f(e3, "Do not have permission to start the camera", new Object[0]);
            Unit unit4 = Unit.a;
        }
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) throws CameraAccessException {
        super.onCreate(bundle);
        v.b(this, null, 3);
        ConstraintLayout constraintLayout = ((e0) K()).a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        AbstractC3188k6.a(constraintLayout);
        s sVarC0 = c0();
        Intrinsics.checkNotNullParameter(this, "view");
        sVarC0.h = this;
        s sVarC02 = c0();
        String[] cameraIdList = ((CameraManager) sVarC02.f).getCameraIdList();
        Intrinsics.checkNotNullExpressionValue(cameraIdList, "getCameraIdList(...)");
        if (cameraIdList.length == 0) {
            QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = (QLiveQrCodeReaderActivity) sVarC02.h;
            if (qLiveQrCodeReaderActivity == null) {
                Intrinsics.m("view");
                throw null;
            }
            qLiveQrCodeReaderActivity.d0();
        } else {
            com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) sVarC02.c;
            DBUser dBUser = dVar.r;
            Integer numValueOf = dBUser != null ? Integer.valueOf(dBUser.getSelfIdentifiedUserType()) : null;
            long personId = dVar.e.getPersonId();
            int i = (numValueOf == null || numValueOf.intValue() != 1) ? R.string.scan_qr_code : R.string.scan_qr_code_teacher;
            QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity2 = (QLiveQrCodeReaderActivity) sVarC02.h;
            if (qLiveQrCodeReaderActivity2 == null) {
                Intrinsics.m("view");
                throw null;
            }
            ((e0) qLiveQrCodeReaderActivity2.K()).d.setText(i);
            com.quizlet.infra.legacysyncengine.managers.g gVar = (com.quizlet.infra.legacysyncengine.managers.g) sVarC02.b;
            String strS = d0.s(new Object[]{Long.valueOf(personId)}, 1, "user_seen_onboarding_dialog_%s", "format(...)");
            SharedPreferences sharedPreferences = gVar.a;
            if (sharedPreferences.getBoolean(strS, false)) {
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity3 = (QLiveQrCodeReaderActivity) sVarC02.h;
                if (qLiveQrCodeReaderActivity3 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                qLiveQrCodeReaderActivity3.b0();
            } else {
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity4 = (QLiveQrCodeReaderActivity) sVarC02.h;
                if (qLiveQrCodeReaderActivity4 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                new f().O(qLiveQrCodeReaderActivity4.getSupportFragmentManager(), f.C);
                sharedPreferences.edit().putBoolean(d0.s(new Object[]{Long.valueOf(personId)}, 1, "user_seen_onboarding_dialog_%s", "format(...)"), true).apply();
            }
        }
        ((e0) K()).c.setOnClickListener(new h(this, 12));
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.google.mlkit.vision.camera.a aVar = this.q;
        if (aVar != null) {
            aVar.a();
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        super.onPause();
        com.google.mlkit.vision.camera.a aVar = this.q;
        if (aVar != null) {
            aVar.c();
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        e0 e0Var = (e0) K();
        e0Var.e.setTitleTextColor(com.quizlet.themes.extensions.a.a(this, R.attr.textColorToolbarInverse));
        v(((e0) K()).e);
        Drawable drawable = getDrawable(R.drawable.ic_sys_close_x);
        if (drawable != null) {
            drawable.setTint(com.quizlet.themes.extensions.a.a(this, R.attr.textColorToolbarInverse));
        }
        com.bumptech.glide.c cVarR = r();
        if (cVarR != null) {
            cVarR.v(drawable);
        }
        com.bumptech.glide.c cVarR2 = r();
        if (cVarR2 != null) {
            cVarR2.z();
        }
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onRequestPermissionsResult(int i, String[] permissions, int[] grantResults) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        super.onRequestPermissionsResult(i, permissions, grantResults);
        boolean zH = AbstractC1016c.h(this, "android.permission.CAMERA");
        s sVarC0 = c0();
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        for (int i2 : grantResults) {
            if (i2 == -1) {
                if (zH) {
                    QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = (QLiveQrCodeReaderActivity) sVarC0.h;
                    if (qLiveQrCodeReaderActivity == null) {
                        Intrinsics.m("view");
                        throw null;
                    }
                    e.a aVar = new e.a(qLiveQrCodeReaderActivity);
                    aVar.f(R.string.qrcode_not_permitted);
                    aVar.c(R.string.qrcode_not_permitted_message);
                    aVar.e(R.string.OK, new b(qLiveQrCodeReaderActivity, 1));
                    aVar.k = aVar.a.getString(R.string.cancel);
                    aVar.l = null;
                    aVar.g();
                    return;
                }
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity2 = (QLiveQrCodeReaderActivity) sVarC0.h;
                if (qLiveQrCodeReaderActivity2 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                e.a aVar2 = new e.a(qLiveQrCodeReaderActivity2);
                aVar2.f(R.string.qrcode_not_permitted);
                aVar2.c(R.string.qrcode_settings_message);
                aVar2.e(R.string.got_it, new b(qLiveQrCodeReaderActivity2, 4));
                aVar2.k = aVar2.a.getString(R.string.cancel);
                aVar2.l = null;
                aVar2.g();
                return;
            }
        }
        QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity3 = (QLiveQrCodeReaderActivity) sVarC0.h;
        if (qLiveQrCodeReaderActivity3 == null) {
            Intrinsics.m("view");
            throw null;
        }
        try {
            s sVarC02 = qLiveQrCodeReaderActivity3.c0();
            PreviewView cameraSourceView = ((e0) qLiveQrCodeReaderActivity3.K()).b;
            Intrinsics.checkNotNullExpressionValue(cameraSourceView, "cameraSourceView");
            qLiveQrCodeReaderActivity3.q = sVarC02.d(cameraSourceView);
        } catch (IllegalArgumentException e) {
            timber.log.c.a.q(e, "This user does not have any available cameras", new Object[0]);
            qLiveQrCodeReaderActivity3.d0();
        }
        qLiveQrCodeReaderActivity3.e0();
        q qVar = new q(sVarC0, 16);
        ((Handler) sVarC0.g).postDelayed(qVar, 10000L);
        sVarC0.i = qVar;
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        super.onResume();
        e0();
    }
}
