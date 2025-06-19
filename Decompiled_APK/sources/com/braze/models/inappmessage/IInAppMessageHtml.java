package com.braze.models.inappmessage;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageHtml extends IInAppMessage {
    String getLocalAssetsDirectoryUrl();

    boolean logButtonClick(String str);

    void setLocalAssetsDirectoryUrl(String str);
}
