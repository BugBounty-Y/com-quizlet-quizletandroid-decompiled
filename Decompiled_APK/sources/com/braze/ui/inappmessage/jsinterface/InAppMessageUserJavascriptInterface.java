package com.braze.ui.inappmessage.jsinterface;

import android.content.Context;
import com.braze.ui.UserJavascriptInterfaceBase;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class InAppMessageUserJavascriptInterface extends UserJavascriptInterfaceBase {

    @NotNull
    private final Context context;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public InAppMessageUserJavascriptInterface(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }
}
