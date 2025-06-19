package com.braze.models.inappmessage;

import com.braze.AbstractC1484j;
import com.braze.C1481g;
import com.braze.enums.inappmessage.MessageType;
import com.braze.events.internal.f0;
import com.braze.managers.C;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import com.braze.support.BrazeLogger;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public abstract class InAppMessageHtmlBase extends InAppMessageBase implements IInAppMessageHtml {
    private String buttonIdClicked;
    private String localAssetsDirectoryUrl;
    private boolean wasButtonClickLogged;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public InAppMessageHtmlBase(JSONObject jsonObject, c0 brazeManager) {
        super(jsonObject, brazeManager, false, false, 12, null);
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
        setOpenUriInWebView(jsonObject.optBoolean("use_webview", true));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$0(String str) {
        return AbstractC1484j.a("Trigger id not found (this is expected for test sends). Not logging html in-app message button click for id: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$1() {
        return "Button Id was null or blank for this html in-app message. Ignoring.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$2() {
        return "Button click already logged for this html in-app message. Ignoring.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$3() {
        return "Cannot log an html in-app message button click because the BrazeManager is null.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logButtonClick$lambda$5(String str, String str2) {
        return android.support.v4.media.session.a.m("Logged button click for button id: ", str, " and trigger id: ", str2);
    }

    @Override // com.braze.models.inappmessage.IInAppMessageHtml
    public String getLocalAssetsDirectoryUrl() {
        return this.localAssetsDirectoryUrl;
    }

    @Override // com.braze.models.inappmessage.IInAppMessageHtml
    public boolean logButtonClick(String buttonId) {
        Intrinsics.checkNotNullParameter(buttonId, "buttonId");
        String triggerId = getTriggerId();
        c0 brazeManager = getBrazeManager();
        if (triggerId == null || triggerId.length() == 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(buttonId, 14), 7, (Object) null);
            return false;
        }
        if (StringsKt.O(buttonId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.models.j(17), 6, (Object) null);
            return false;
        }
        if (this.wasButtonClickLogged && getMessageType() != MessageType.HTML) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.models.j(18), 6, (Object) null);
            return false;
        }
        if (brazeManager == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.models.j(19), 6, (Object) null);
            return false;
        }
        com.braze.models.i iVarI = com.braze.models.outgoing.event.b.g.i(triggerId, buttonId);
        if (iVarI != null) {
            ((C1500m) brazeManager).a(iVarI);
        }
        this.buttonIdClicked = buttonId;
        this.wasButtonClickLogged = true;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(10, buttonId, triggerId), 7, (Object) null);
        return true;
    }

    @Override // com.braze.models.inappmessage.InAppMessageBase, com.braze.models.inappmessage.IInAppMessage
    public void onAfterClosed() {
        String triggerId;
        String str;
        c0 brazeManager;
        super.onAfterClosed();
        if (!this.wasButtonClickLogged || (triggerId = getTriggerId()) == null || StringsKt.O(triggerId) || (str = this.buttonIdClicked) == null || StringsKt.O(str) || (brazeManager = getBrazeManager()) == null) {
            return;
        }
        com.braze.triggers.events.d triggerEvent = new com.braze.triggers.events.d(getTriggerId(), this.buttonIdClicked);
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        ((C1500m) brazeManager).d.b(new f0(triggerEvent), f0.class);
    }

    @Override // com.braze.models.inappmessage.IInAppMessageHtml
    public void setLocalAssetsDirectoryUrl(String str) {
        this.localAssetsDirectoryUrl = str;
    }

    @Override // com.braze.models.inappmessage.InAppMessageBase, com.braze.models.inappmessage.IInAppMessage
    public void setLocalPrefetchedAssetPaths(Map<String, String> remotePathToLocalAssetMap) {
        Intrinsics.checkNotNullParameter(remotePathToLocalAssetMap, "remotePathToLocalAssetMap");
        if (remotePathToLocalAssetMap.isEmpty()) {
            return;
        }
        setLocalAssetsDirectoryUrl(((String[]) remotePathToLocalAssetMap.values().toArray(new String[0]))[0]);
    }
}
