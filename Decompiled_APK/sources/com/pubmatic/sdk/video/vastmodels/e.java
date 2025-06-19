package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.pubmatic.sdk.common.utility.o;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;

/* loaded from: classes2.dex */
public class e implements com.pubmatic.sdk.video.xmlserialiser.b {
    private String a;
    private String b;
    private int c;
    private int d;
    private int e;
    private boolean f;
    private boolean g = true;
    private String h;
    private String i;

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.a = aVar.getAttributeValue("delivery");
        this.b = aVar.getAttributeValue(DBUserFields.Names.USER_UPGRADE_TYPE);
        this.c = o.getIntegerValue(aVar.getAttributeValue("bitrate"));
        this.d = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_WIDTH));
        this.e = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_HEIGHT));
        this.f = o.getBooleanValue(aVar.getAttributeValue("scalable"));
        String attributeValue = aVar.getAttributeValue("maintainAspectRatio");
        if (attributeValue != null && !attributeValue.isEmpty()) {
            this.g = o.getBooleanValue(attributeValue);
        }
        this.h = aVar.getNodeValue();
        this.i = aVar.getAttributeValue("fileSize");
    }

    public int getBitrate() {
        return this.c;
    }

    public String getDelivery() {
        return this.a;
    }

    public String getFileSize() {
        return this.i;
    }

    public int getHeight() {
        return this.e;
    }

    public boolean getMaintainAspectRatio() {
        return this.g;
    }

    public String getMediaFileURL() {
        return this.h;
    }

    public boolean getScalable() {
        return this.f;
    }

    public String getType() {
        return this.b;
    }

    public int getWidth() {
        return this.d;
    }

    @NonNull
    public String toString() {
        return "Type: " + this.b + ", bitrate: " + this.c + ", w: " + this.d + ", h: " + this.e + ", URL: " + this.h;
    }
}
