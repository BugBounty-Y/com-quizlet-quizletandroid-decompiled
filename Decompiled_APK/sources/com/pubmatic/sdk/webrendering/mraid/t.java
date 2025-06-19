package com.pubmatic.sdk.webrendering.mraid;

import org.json.JSONObject;

/* loaded from: classes2.dex */
public interface t {
    void close();

    void createCalendarEvent(JSONObject jSONObject, boolean z);

    void expand(String str, boolean z);

    boolean isUserInteracted(boolean z);

    void listenerChanged(String str, boolean z);

    void open(String str, boolean z);

    void playVideo(String str, boolean z);

    void resize(int i, int i2, int i3, int i4, boolean z, boolean z2);

    void setOrientation(boolean z, String str, boolean z2);

    void storePicture(String str, boolean z);

    void unload();
}
