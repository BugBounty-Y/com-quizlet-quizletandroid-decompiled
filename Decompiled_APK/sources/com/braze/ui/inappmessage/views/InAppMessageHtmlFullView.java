package com.braze.ui.inappmessage.views;

import android.content.Context;
import android.util.AttributeSet;
import com.braze.ui.R$id;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public class InAppMessageHtmlFullView extends InAppMessageHtmlBaseView {
    public InAppMessageHtmlFullView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    @Override // com.braze.ui.inappmessage.views.InAppMessageHtmlBaseView
    public int getWebViewViewId() {
        return R$id.com_braze_inappmessage_html_full_webview;
    }
}
