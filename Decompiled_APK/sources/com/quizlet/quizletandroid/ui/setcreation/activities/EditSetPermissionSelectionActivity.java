package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.content.Intent;
import android.os.Bundle;
import android.widget.FrameLayout;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.pubmatic.sdk.video.c;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4602f;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class EditSetPermissionSelectionActivity extends com.quizlet.ads.ui.activity.d {
    public static final String v;
    public com.quizlet.quizletandroid.util.j q;
    public boolean r;
    public boolean s;
    public androidx.work.impl.model.c t;
    public com.quizlet.shared.usecase.folderstudymaterials.d u;

    static {
        Intrinsics.checkNotNullExpressionValue("EditSetPermissionSelectionActivity", "getSimpleName(...)");
        v = "EditSetPermissionSelectionActivity";
    }

    public EditSetPermissionSelectionActivity() {
        super(7);
        this.q = com.quizlet.quizletandroid.util.j.c;
    }

    public static final n b0(EditSetPermissionSelectionActivity editSetPermissionSelectionActivity, com.quizlet.quizletandroid.util.j permissionAccess) {
        int i;
        boolean z = editSetPermissionSelectionActivity.r;
        Intrinsics.checkNotNullParameter(permissionAccess, "permissionAccess");
        int iOrdinal = permissionAccess.ordinal();
        if (iOrdinal == 0) {
            i = z ? R.string.visibility_permission_picker_justme : R.string.editability_permission_picker_justme;
        } else if (iOrdinal == 1) {
            i = z ? R.string.visibility_permission_picker_password : R.string.editability_permission_picker_password;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i = z ? R.string.visibility_permission_picker_everyone : R.string.editability_permission_picker_everyone;
        }
        String string = editSetPermissionSelectionActivity.getString(i);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return new n(string, permissionAccess, editSetPermissionSelectionActivity.q == permissionAccess);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return v;
    }

    @Override // com.quizlet.baseui.base.f
    public final FrameLayout J() {
        return (FrameLayout) ((C4602f) K()).b.d;
    }

    @Override // com.quizlet.baseui.base.f
    public final com.google.android.material.tabs.l L() {
        return (QTabLayout) ((C4602f) K()).b.c;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        return (Toolbar) ((C4602f) K()).b.f;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        C4602f c4602fA = C4602f.a(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(c4602fA, "inflate(...)");
        return c4602fA;
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i != 10000 || i2 == 1234 || intent == null) {
            return;
        }
        String stringExtra = intent.getStringExtra(DBStudySetFields.Names.PASSWORD);
        Intent intent2 = new Intent();
        com.quizlet.quizletandroid.util.j jVar = com.quizlet.quizletandroid.util.j.a;
        intent2.putExtra("current_permission_access", 1);
        intent2.putExtra(DBStudySetFields.Names.PASSWORD, stringExtra);
        intent2.putExtra("has_changed_password_use", true);
        intent2.putExtra("changing_set_visibility", this.r);
        setResult(c.a.DEFAULT_MEDIA_URI_TIMEOUT, intent2);
        finish();
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        setResult(1234);
        super.onBackPressed();
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        FrameLayout frameLayout = ((C4602f) K()).a;
        Intrinsics.checkNotNullExpressionValue(frameLayout, "getRoot(...)");
        AbstractC3188k6.a(frameLayout);
        this.q = com.quizlet.quizletandroid.util.j.values()[getIntent().getIntExtra("current_permission_access", 0)];
        this.r = getIntent().getBooleanExtra("changing_set_visibility", false);
        this.s = getIntent().getBooleanExtra("hasPasswordAlready", false);
        RecyclerView editSetLanguageList = ((C4602f) K()).c;
        Intrinsics.checkNotNullExpressionValue(editSetLanguageList, "editSetLanguageList");
        editSetLanguageList.setLayoutManager(new LinearLayoutManager(1));
        ArrayList arrayList = new ArrayList();
        com.quizlet.shared.usecase.folderstudymaterials.d dVar = this.u;
        if (dVar == null) {
            Intrinsics.m("permissionFeature");
            throw null;
        }
        androidx.work.impl.model.c userProps = this.t;
        if (userProps == null) {
            Intrinsics.m("loggedInUserManagerProperties");
            throw null;
        }
        dVar.getClass();
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        com.google.android.gms.dynamite.d.e(userProps.u()).i(new com.quizlet.billing.manager.b(this, arrayList, 13), new com.quizlet.billing.manager.d(timber.log.c.a, 10));
    }
}
