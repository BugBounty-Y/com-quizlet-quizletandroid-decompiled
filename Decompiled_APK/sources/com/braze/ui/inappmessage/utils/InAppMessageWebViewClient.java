package com.braze.ui.inappmessage.utils;

import android.content.Context;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.ui.BrazeWebViewClient;
import com.braze.ui.inappmessage.listeners.IInAppMessageWebViewClientListener;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class InAppMessageWebViewClient extends BrazeWebViewClient {

    @NotNull
    private final IInAppMessage inAppMessage;
    private final IInAppMessageWebViewClientListener inAppMessageWebViewClientListener;

    public /* synthetic */ InAppMessageWebViewClient(Context context, IInAppMessage iInAppMessage, IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener, String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, iInAppMessage, iInAppMessageWebViewClientListener, (i & 8) != 0 ? null : str);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public InAppMessageWebViewClient(@NotNull Context context, @NotNull IInAppMessage inAppMessage, IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener, String str) {
        super(context, BrazeWebViewClient.Type.IN_APP_MESSAGE, inAppMessage, iInAppMessageWebViewClientListener, null, str);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        this.inAppMessage = inAppMessage;
        this.inAppMessageWebViewClientListener = iInAppMessageWebViewClientListener;
    }
}
