package com.pubmatic.sdk.webrendering.ui;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import androidx.annotation.NonNull;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public class h extends Dialog {
    private g a;

    @NonNull
    private WeakReference<Context> b;
    private boolean c;
    private Integer d;

    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            h.this.dismiss();
        }
    }

    public h(@NonNull Context context, @NonNull WebView webView, @NonNull g gVar) {
        super(context, R.style.Theme.Black.NoTitleBar.Fullscreen);
        this.b = new WeakReference<>(context);
        a(gVar);
        setContentView(a(webView, -1, -1));
    }

    private void a(g gVar) {
        this.a = gVar;
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        g gVar = this.a;
        if (gVar != null) {
            gVar.onClose();
        }
        if (this.c && this.d != null) {
            Context context = this.b.get();
            if (context instanceof Activity) {
                ((Activity) context).setRequestedOrientation(this.d.intValue());
            }
        }
        this.a = null;
        super.dismiss();
    }

    @Override // android.app.Dialog
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (bundle != null) {
            dismiss();
        }
    }

    public void show(int i) {
        Activity ownerActivity;
        show();
        if (!this.c || (ownerActivity = getOwnerActivity()) == null) {
            return;
        }
        this.d = Integer.valueOf(ownerActivity.getRequestedOrientation());
        a(ownerActivity, i);
    }

    @NonNull
    private FrameLayout a(@NonNull View view, int i, int i2) {
        FrameLayout frameLayout = new FrameLayout(view.getContext());
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(i, i2);
        layoutParams.gravity = 17;
        layoutParams.setMargins(0, 0, 0, 0);
        frameLayout.addView(view, layoutParams);
        ImageButton imageButtonCreateSkipButton = com.pubmatic.sdk.webrendering.a.createSkipButton(view.getContext(), com.pubmatic.sdk.webrendering.e.pob_close_btn, com.pubmatic.sdk.webrendering.d.pob_ic_close_black_24dp);
        frameLayout.addView(imageButtonCreateSkipButton);
        imageButtonCreateSkipButton.setOnClickListener(new a());
        return frameLayout;
    }

    private void a(@NonNull Activity activity, int i) {
        if (i == 0) {
            activity.setRequestedOrientation(-1);
        } else if (i == 2) {
            activity.setRequestedOrientation(6);
        } else if (i == 1) {
            activity.setRequestedOrientation(7);
        }
    }
}
