package com.pubmatic.sdk.webrendering.ui;

import android.content.Context;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class f extends FrameLayout {

    @NonNull
    private final Button a;

    public f(@NonNull Context context) {
        super(context);
        View.inflate(context, com.pubmatic.sdk.webrendering.g.pob_custom_product_layout, this);
        Button button = (Button) findViewById(com.pubmatic.sdk.webrendering.e.pob_install_btn);
        this.a = button;
        button.setText(com.pubmatic.sdk.webrendering.a.getLocalizedStringForKey(context, "pob_openwrap_install_button_title", "Install"));
        setOnClickListener(null);
    }

    public void setInstallButtonClickListener(View.OnClickListener onClickListener) {
        this.a.setOnClickListener(onClickListener);
    }
}
