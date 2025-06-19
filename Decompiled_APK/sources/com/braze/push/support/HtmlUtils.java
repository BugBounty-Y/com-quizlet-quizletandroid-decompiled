package com.braze.push.support;

import android.text.Html;
import android.text.Spanned;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.models.outgoing.a;
import com.braze.support.BrazeLogger;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class HtmlUtils {

    @NotNull
    private static final String TAG = BrazeLogger.INSTANCE.getBrazeLogTag("HtmlUtils");

    @NotNull
    public static final CharSequence getHtmlSpannedTextIfEnabled(@NotNull String str, @NotNull BrazeConfigurationProvider configurationProvider) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        if (StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(20), 14, (Object) null);
            return str;
        }
        if (!configurationProvider.isPushNotificationHtmlRenderingEnabled()) {
            return str;
        }
        Spanned spannedFromHtml = Html.fromHtml(str, 0);
        Intrinsics.d(spannedFromHtml);
        return spannedFromHtml;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getHtmlSpannedTextIfEnabled$lambda$0() {
        return "Cannot create html spanned text on blank text. Returning blank string.";
    }
}
