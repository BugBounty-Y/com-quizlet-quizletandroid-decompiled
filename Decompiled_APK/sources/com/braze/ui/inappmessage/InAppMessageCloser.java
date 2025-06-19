package com.braze.ui.inappmessage;

@Deprecated
/* loaded from: classes.dex */
public class InAppMessageCloser {
    private final IInAppMessageViewWrapper mInAppMessageViewWrapper;

    public InAppMessageCloser(IInAppMessageViewWrapper iInAppMessageViewWrapper) {
        this.mInAppMessageViewWrapper = iInAppMessageViewWrapper;
    }

    public void close(boolean z) {
        this.mInAppMessageViewWrapper.getInAppMessage().setAnimateOut(z);
        this.mInAppMessageViewWrapper.close();
    }
}
