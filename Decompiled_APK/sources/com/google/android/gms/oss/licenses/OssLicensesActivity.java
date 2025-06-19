package com.google.android.gms.oss.licenses;

import android.os.Bundle;
import android.view.MenuItem;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.work.impl.model.v;
import com.google.android.gms.auth.api.signin.internal.h;
import com.google.android.gms.common.api.internal.y;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.oss_licenses.zze;
import com.google.android.gms.tasks.m;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class OssLicensesActivity extends AbstractActivityC0055k {
    public zze c;
    public String d = "";
    public ScrollView e = null;
    public TextView f = null;
    public int g = 0;
    public m h;
    public m i;
    public com.quizlet.data.interactor.school.b j;
    public v k;

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.libraries_social_licenses_license_loading);
        this.j = com.quizlet.data.interactor.school.b.q(this);
        this.c = (zze) getIntent().getParcelableExtra("license");
        if (r() != null) {
            r().A(this.c.a);
            r().t();
            r().s(true);
            r().x();
        }
        ArrayList arrayList = new ArrayList();
        m mVarC = ((c) this.j.b).c(0, new y(this.c, 1));
        this.h = mVarC;
        arrayList.add(mVarC);
        m mVarC2 = ((c) this.j.b).c(0, new b(getPackageName(), 0));
        this.i = mVarC2;
        arrayList.add(mVarC2);
        S3.j(arrayList).addOnCompleteListener(new h(this, 26));
    }

    @Override // android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() != 16908332) {
            return super.onOptionsItemSelected(menuItem);
        }
        finish();
        return true;
    }

    @Override // android.app.Activity
    public final void onRestoreInstanceState(Bundle bundle) {
        super.onRestoreInstanceState(bundle);
        this.g = bundle.getInt("scroll_pos");
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        TextView textView = this.f;
        if (textView == null || this.e == null) {
            return;
        }
        bundle.putInt("scroll_pos", this.f.getLayout().getLineStart(textView.getLayout().getLineForVertical(this.e.getScrollY())));
    }
}
