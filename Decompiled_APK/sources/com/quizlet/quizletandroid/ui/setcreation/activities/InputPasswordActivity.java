package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.FrameLayout;
import android.widget.Toast;
import androidx.activity.v;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.pubmatic.sdk.video.c;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.partskit.widgets.QEditText;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4603g;
import com.quizlet.quizletandroid.databinding.J;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class InputPasswordActivity extends com.quizlet.ads.ui.activity.d {
    public static final String t;
    public UserInfoCache q;
    public boolean r;
    public String s;

    static {
        Intrinsics.checkNotNullExpressionValue("InputPasswordActivity", "getSimpleName(...)");
        t = "InputPasswordActivity";
    }

    public InputPasswordActivity() {
        super(8);
        this.s = "";
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(R.menu.input_password_menu);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return t;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_input_password, (ViewGroup) null, false);
        int i = R.id.appbar;
        View viewC = AbstractC3375o2.c(R.id.appbar, viewInflate);
        if (viewC != null) {
            J jA = J.a(viewC);
            QEditText qEditText = (QEditText) AbstractC3375o2.c(R.id.editTextPassword, viewInflate);
            if (qEditText != null) {
                C4603g c4603g = new C4603g((FrameLayout) viewInflate, jA, qEditText);
                Intrinsics.checkNotNullExpressionValue(c4603g, "inflate(...)");
                return c4603g;
            }
            i = R.id.editTextPassword;
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final QEditText b0() {
        QEditText editTextPassword = ((C4603g) K()).c;
        Intrinsics.checkNotNullExpressionValue(editTextPassword, "editTextPassword");
        return editTextPassword;
    }

    public final boolean c0() {
        String strValueOf = String.valueOf(b0().getText());
        if (strValueOf.length() == 0) {
            return false;
        }
        if (!this.r) {
            this.s = strValueOf;
            Editable text = b0().getText();
            if (text != null) {
                text.clear();
            }
            b0().setHint(getString(R.string.set_password_confirm_hint));
            this.r = true;
            b0().requestFocus();
            return false;
        }
        if (Intrinsics.b(this.s, strValueOf)) {
            Intent intent = new Intent();
            intent.putExtra(DBStudySetFields.Names.PASSWORD, strValueOf);
            setResult(c.a.DEFAULT_MEDIA_URI_TIMEOUT, intent);
            finish();
            return true;
        }
        Toast.makeText(this, getString(R.string.set_wrong_password_message), 1).show();
        b0().setHint(getString(R.string.set_password_hint));
        Editable text2 = b0().getText();
        if (text2 != null) {
            text2.clear();
        }
        this.r = false;
        this.s = "";
        return false;
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
        FrameLayout frameLayout = ((C4603g) K()).a;
        Intrinsics.checkNotNullExpressionValue(frameLayout, "getRoot(...)");
        AbstractC3188k6.a(frameLayout);
        b0().setOnEditorActionListener(new com.quizlet.login.recovery.forgotpassword.ui.b(this, 4));
        v(((C4603g) K()).b.c);
        com.bumptech.glide.c cVarR = r();
        if (cVarR != null) {
            cVarR.s(true);
            cVarR.t();
            cVarR.A("");
        }
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        return item.getItemId() == R.id.menu_input_password_complete ? c0() : super.onOptionsItemSelected(item);
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        View currentFocus = getCurrentFocus();
        if (currentFocus != null) {
            Object systemService = getSystemService("input_method");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
            ((InputMethodManager) systemService).hideSoftInputFromWindow(currentFocus.getWindowToken(), 0);
        }
        super.onPause();
    }

    @Override // android.app.Activity
    public final boolean onPrepareOptionsMenu(Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        super.onPrepareOptionsMenu(menu);
        UserInfoCache userInfoCache = this.q;
        if (userInfoCache != null) {
            androidx.work.impl.model.f.b(menu, R.id.menu_input_password_complete, userInfoCache.b());
            return true;
        }
        Intrinsics.m("userInfoCache");
        throw null;
    }
}
