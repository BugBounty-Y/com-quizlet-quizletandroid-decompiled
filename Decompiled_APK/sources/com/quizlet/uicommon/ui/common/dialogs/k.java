package com.quizlet.uicommon.ui.common.dialogs;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class k extends e {
    public final String t;

    public k(Context context, String str) {
        super(context);
        this.t = str;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.e, androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        View viewInflate = getLayoutInflater().inflate(R.layout.dialog_qprogress, (ViewGroup) null);
        TextView textView = (TextView) viewInflate.findViewById(R.id.qprogress_message);
        String str = this.t;
        textView.setVisibility(TextUtils.isEmpty(str) ? 8 : 0);
        textView.setText(str);
        this.m.setVisibility(0);
        this.m.addView(viewInflate);
    }
}
