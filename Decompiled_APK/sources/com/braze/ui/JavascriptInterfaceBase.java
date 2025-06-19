package com.braze.ui;

import android.content.Context;
import android.webkit.JavascriptInterface;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.braze.Braze;
import com.braze.models.outgoing.BrazeProperties;
import com.braze.support.BrazeLogger;
import com.braze.support.w;
import java.math.BigDecimal;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public abstract class JavascriptInterfaceBase {

    @NotNull
    private final Context context;

    public JavascriptInterfaceBase(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPurchaseWithJSON$lambda$0(String str) {
        return B.h("Failed to parse logPurchaseWithJSON price value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPurchaseWithJSON$lambda$1(String str) {
        return B.h("Failed to parse logPurchaseWithJSON quantity value '", str, '\'');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String parseProperties$lambda$2(String str) {
        return AbstractC0147y.d("Failed to parse properties JSON String: ", str);
    }

    @JavascriptInterface
    public final void changeUser(@NotNull String userId, String str) {
        Intrinsics.checkNotNullParameter(userId, "userId");
        Braze.Companion.getInstance(this.context).changeUser(userId, str);
    }

    @JavascriptInterface
    public abstract void logButtonClick(String str);

    @JavascriptInterface
    public abstract void logClick();

    @JavascriptInterface
    public final void logCustomEventWithJSON(String str, String str2) {
        Braze.Companion.getInstance(this.context).logCustomEvent(str, parseProperties(str2));
    }

    @JavascriptInterface
    public final void logPurchaseWithJSON(String str, @NotNull String price, String str2, @NotNull String quantity, String str3) {
        Intrinsics.checkNotNullParameter(price, "price");
        Intrinsics.checkNotNullParameter(quantity, "quantity");
        BrazeProperties properties = parseProperties(str3);
        Double dE = C.e(price);
        if (dE == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(price, 28), 6, (Object) null);
            return;
        }
        Integer intOrNull = StringsKt.toIntOrNull(quantity);
        if (intOrNull == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(quantity, 29), 6, (Object) null);
        } else {
            Braze.Companion.getInstance(this.context).logPurchase(str, str2, new BigDecimal(dE.toString()), intOrNull.intValue(), properties);
        }
    }

    public final BrazeProperties parseProperties(String str) {
        if (str == null) {
            return null;
        }
        try {
            if (str.equals("undefined") || str.equals("null")) {
                return null;
            }
            return new BrazeProperties(new JSONObject(str));
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new w(str, 27), 4, (Object) null);
            return null;
        }
    }

    @JavascriptInterface
    public final void requestImmediateDataFlush() {
        Braze.Companion.getInstance(this.context).requestImmediateDataFlush();
    }
}
