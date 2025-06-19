package com.quizlet.quizletandroid.ui.usersettings.fragments;

import android.app.ProgressDialog;
import android.graphics.PorterDuff;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.ProgressBar;
import androidx.viewbinding.a;
import androidx.work.impl.model.f;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public abstract class ChangeSettingsBaseFragment<T extends androidx.viewbinding.a> extends BaseFragment<T> {
    public IQuizletApiClient e;
    public com.quizlet.quizletandroid.ui.usersettings.d f;
    public EventLogger g;
    public ProgressDialog h;
    public boolean i = false;
    public final io.reactivex.rxjava3.disposables.a j = new io.reactivex.rxjava3.disposables.a();

    public final void Q(boolean z) {
        if (z) {
            if (isAdded()) {
                this.h.show();
            }
        } else {
            ProgressDialog progressDialog = this.h;
            if (progressDialog == null || !progressDialog.isShowing()) {
                return;
            }
            this.h.dismiss();
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setHasOptionsMenu(true);
        ProgressDialog progressDialog = new ProgressDialog(getContext(), R.style.QuizletProgressDialog);
        progressDialog.setCancelable(false);
        progressDialog.setProgressStyle(0);
        this.h = progressDialog;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreateOptionsMenu(Menu menu, MenuInflater menuInflater) {
        super.onCreateOptionsMenu(menu, menuInflater);
        menuInflater.inflate(R.menu.user_settings_edit_menu, menu);
        ((ProgressBar) menu.findItem(R.id.menu_user_settings_progress).getActionView().findViewById(R.id.progress_bar)).getIndeterminateDrawable().setColorFilter(com.quizlet.themes.extensions.a.a(getContext(), R.attr.SysColorCard), PorterDuff.Mode.SRC_IN);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPrepareOptionsMenu(Menu menu) {
        super.onPrepareOptionsMenu(menu);
        f.b(menu, R.id.menu_user_settings_progress, false);
        MenuItem menuItemFindItem = menu.findItem(R.id.menu_user_settings_confirm);
        if (menuItemFindItem != null) {
            menuItemFindItem.setVisible(true);
            menuItemFindItem.setEnabled(this.i);
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onStop() {
        this.j.d();
        super.onStop();
    }
}
