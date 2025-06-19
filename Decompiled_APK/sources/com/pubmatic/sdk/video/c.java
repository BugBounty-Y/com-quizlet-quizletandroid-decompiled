package com.pubmatic.sdk.video;

import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdLoader;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.common.log.POBLog;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class c {
    private int a;
    private int b;
    private int c;
    private int d;
    private int e;
    private int f;
    private int g;
    private boolean h;
    private final int i;
    private final boolean j;
    private final boolean k;

    public static class a {
        public static final int DEFAULT_ENDCARD_SKIP_AFTER = 5;
        public static final int DEFAULT_MEDIA_URI_TIMEOUT = 10000;
        public static final boolean DEFAULT_PLAY_ON_MUTE = true;
        public static final int DEFAULT_SKIP = 1;
        public static final int DEFAULT_VIDEO_SKIP_AFTER = 7;
        public static final int DEFAULT_WRAPPER_URI_TIMEOUT = 5000;
        private int a;
        private int b;
        private int d;
        private boolean h = true;
        private int i = 5;
        private boolean j = false;
        private boolean k = false;
        private int c = 1;
        private int e = 7;
        private int f = 5000;
        private int g = DEFAULT_MEDIA_URI_TIMEOUT;

        public a(int i, int i2) {
            this.a = i;
            this.b = i2;
        }

        private static int a(boolean z) {
            return z ? 0 : 7;
        }

        @NonNull
        public static c createVastConfig(JSONObject jSONObject, boolean z, boolean z2, boolean z3, @NonNull String str) {
            c cVarBuild = new a(0, 0).build(z);
            if (jSONObject != null) {
                JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("ext");
                if (jSONObjectOptJSONObject != null && jSONObjectOptJSONObject.length() > 0) {
                    JSONObject jSONObjectOptJSONObject2 = jSONObjectOptJSONObject.optJSONObject(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO);
                    if (jSONObjectOptJSONObject2 == null || jSONObjectOptJSONObject2.length() <= 0) {
                        POBLog.warn("ConfigBuilder", "Null/empty video response parameter.", new Object[0]);
                        return cVarBuild;
                    }
                    POBLog.info("ConfigBuilder", assistantMode.refactored.a.j("Video config: ", jSONObjectOptJSONObject2), new Object[0]);
                    a aVar = new a(jSONObjectOptJSONObject2.optInt("minduration"), jSONObjectOptJSONObject2.optInt("maxduration"));
                    aVar.skip(jSONObjectOptJSONObject2.optInt("skip", 1));
                    aVar.skipMin(jSONObjectOptJSONObject2.optInt("skipmin"));
                    aVar.setSkipAfterCompletionEnabled(z2);
                    if (-9999 != jSONObjectOptJSONObject2.optInt(DTBAdLoader.APS_VIDEO_SKIP_AFTER, -9999)) {
                        aVar.setSkipAfterCompletionEnabled(false);
                    }
                    aVar.skipAfter(jSONObjectOptJSONObject2.optInt(DTBAdLoader.APS_VIDEO_SKIP_AFTER, a(z2)));
                    aVar.setPlayOnMute(z3);
                    JSONArray jSONArrayOptJSONArray = jSONObjectOptJSONObject2.optJSONArray("playbackmethod");
                    if (jSONArrayOptJSONArray != null && jSONArrayOptJSONArray.length() > 0) {
                        try {
                            int iIntValue = ((Integer) jSONArrayOptJSONArray.get(0)).intValue();
                            if (DTBAdSize.AAX_INTERSTITIAL_AD_SIZE.equals(str)) {
                                if (iIntValue == 1) {
                                    aVar.setPlayOnMute(false);
                                } else if (iIntValue == 2) {
                                    aVar.setPlayOnMute(true);
                                }
                            } else if (iIntValue == 5) {
                                aVar.setPlayOnMute(false);
                            } else if (iIntValue == 6) {
                                aVar.setPlayOnMute(true);
                            }
                        } catch (JSONException e) {
                            POBLog.warn("ConfigBuilder", "Failed to parse playbackmethod, %s", e.toString());
                        }
                    }
                    JSONObject jSONObjectOptJSONObject3 = jSONObjectOptJSONObject2.optJSONObject("clientconfig");
                    if (jSONObjectOptJSONObject3 != null && jSONObjectOptJSONObject3.length() > 0) {
                        aVar.setBackButtonEnabled(jSONObjectOptJSONObject3.optBoolean("enablehardwarebackbutton", false));
                        JSONObject jSONObjectOptJSONObject4 = jSONObjectOptJSONObject3.optJSONObject("timeouts");
                        if (jSONObjectOptJSONObject4 != null) {
                            aVar.wrapperUriTimeout(jSONObjectOptJSONObject4.optInt("wrapperTagURI"));
                            aVar.mediaUriTimeout(jSONObjectOptJSONObject4.optInt("mediaFileURI"));
                        }
                        JSONObject jSONObjectOptJSONObject5 = jSONObjectOptJSONObject3.optJSONObject("companion");
                        if (jSONObjectOptJSONObject5 != null) {
                            aVar.endCardSkipAfter(jSONObjectOptJSONObject5.optInt(DTBAdLoader.APS_VIDEO_SKIP_AFTER, 5));
                        }
                    }
                    return aVar.build(z);
                }
                POBLog.warn("ConfigBuilder", "Null/empty extension response parameter.", new Object[0]);
            }
            return cVarBuild;
        }

        public c build(boolean z) {
            return new c(this, z);
        }

        public a endCardSkipAfter(int i) {
            this.i = i;
            return this;
        }

        public a mediaUriTimeout(int i) {
            if (i > this.g) {
                this.g = i;
            }
            return this;
        }

        public a setBackButtonEnabled(boolean z) {
            this.j = z;
            return this;
        }

        public a setPlayOnMute(boolean z) {
            this.h = z;
            return this;
        }

        public a setSkipAfterCompletionEnabled(boolean z) {
            this.k = z;
            return this;
        }

        public a skip(int i) {
            this.c = i;
            return this;
        }

        public a skipAfter(int i) {
            this.e = i;
            return this;
        }

        public a skipMin(int i) {
            this.d = i;
            return this;
        }

        public a wrapperUriTimeout(int i) {
            if (i > this.f) {
                this.f = i;
            }
            return this;
        }
    }

    public int getEndCardSkipAfter() {
        return this.i;
    }

    public int getMaxDuration() {
        return this.b;
    }

    public int getMediaUriTimeout() {
        return this.g;
    }

    public int getMinDuration() {
        return this.a;
    }

    public int getSkip() {
        return this.c;
    }

    public int getSkipAfter() {
        return this.e;
    }

    public int getSkipMin() {
        return this.d;
    }

    public int getWrapperUriTimeout() {
        return this.f;
    }

    public boolean isBackButtonEnabled() {
        return this.j;
    }

    public boolean isPlayOnMute() {
        return this.h;
    }

    public boolean isSkipAfterCompletionEnabled() {
        return this.k;
    }

    private c(@NonNull a aVar, boolean z) {
        this.a = aVar.a;
        this.b = aVar.b;
        if (z) {
            this.c = aVar.c;
        }
        this.d = aVar.d;
        this.e = aVar.e;
        this.f = aVar.f;
        this.g = aVar.g;
        this.h = aVar.h;
        this.i = aVar.i;
        this.j = aVar.j;
        this.k = aVar.k;
    }
}
