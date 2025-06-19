package com.onetrust.otpublishers.headless.UI.DataModels;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class c {
    public String a;
    public String b;
    public String c;
    public String d;
    public String e;
    public String f;
    public String g;
    public String h;
    public ArrayList i;
    public ArrayList j;
    public String k;

    public final String toString() {
        StringBuilder sb = new StringBuilder("OTUCPurposesModel{Id='");
        sb.append(this.a);
        sb.append("', Label='");
        sb.append(this.b);
        sb.append("', Description='");
        sb.append(this.c);
        sb.append("', Status='");
        sb.append(this.d);
        sb.append("', NewVersionAvailable='");
        sb.append(this.e);
        sb.append("', Type='");
        sb.append(this.f);
        sb.append("', LifeSpan='");
        sb.append(this.g);
        sb.append("', Version='");
        sb.append(this.h);
        sb.append("', otUcPurposesTopicsModels=");
        sb.append(this.i);
        sb.append(", otUcPurposesCustomPreferencesModels=");
        sb.append(this.j);
        sb.append(", DefaultConsentStatus='null', UserConsentStatus='");
        return android.support.v4.media.session.a.t(sb, this.k, "'}");
    }
}
