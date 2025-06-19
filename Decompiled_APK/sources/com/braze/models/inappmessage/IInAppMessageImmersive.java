package com.braze.models.inappmessage;

import com.braze.enums.inappmessage.ImageStyle;
import java.util.List;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IInAppMessageImmersive extends IInAppMessage {
    ImageStyle getImageStyle();

    List<MessageButton> getMessageButtons();

    boolean logButtonClick(MessageButton messageButton);
}
