package org.prebid.mobile.rendering.models.openrtb;

import android.support.v4.media.session.a;
import android.text.TextUtils;
import com.amazon.device.ads.DtbDeviceData;
import com.appsflyer.AdRevenueScheme;
import com.pubmatic.sdk.common.base.c;
import com.quizlet.db.data.models.base.AssociationNames;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.TargetingParams;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.App;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.BaseBid;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Device;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Ext;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Imp;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Native;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Regs;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.User;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.apps.Publisher;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.imps.Banner;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.imps.Video;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.imps.pmps.Format;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.source.Source;

/* loaded from: classes3.dex */
public class BidRequest extends BaseBid {
    public String a;
    public App b = null;
    public Device c = null;
    public final ArrayList d = new ArrayList();
    public Regs e = null;
    public User f = null;
    public Source g = null;
    public Ext h = null;

    public final Device a() {
        if (this.c == null) {
            this.c = new Device();
        }
        return this.c;
    }

    public final JSONObject b() throws JSONException {
        JSONObject jSONObject;
        JSONObject jSONObject2;
        JSONObject jSONObject3;
        JSONObject jSONObject4;
        JSONObject jSONObject5;
        JSONArray jSONArray;
        JSONObject jSONObject6;
        ArrayList arrayList;
        int i;
        JSONObject jSONObject7;
        JSONObject jSONObject8;
        Object obj;
        JSONObject jSONObject9;
        JSONObject jSONObject10 = new JSONObject();
        ArrayList arrayList2 = this.d;
        Object obj2 = null;
        if (arrayList2 != null && arrayList2.size() > 0) {
            JSONArray jSONArray2 = new JSONArray();
            int i2 = 0;
            while (i2 < arrayList2.size()) {
                Imp imp = (Imp) arrayList2.get(i2);
                imp.getClass();
                JSONObject jSONObject11 = new JSONObject();
                imp.k = jSONObject11;
                jSONObject11.putOpt("id", imp.a);
                imp.k.putOpt("displaymanager", imp.b);
                imp.k.putOpt("displaymanagerver", imp.c);
                imp.k.putOpt("instl", imp.d);
                imp.k.putOpt("tagid", obj2);
                imp.k.putOpt("rwdd", obj2);
                imp.k.putOpt("clickbrowser", imp.j);
                imp.k.putOpt("secure", imp.e);
                JSONObject jSONObject12 = imp.k;
                Banner banner = imp.f;
                if (banner != null) {
                    JSONObject jSONObject13 = new JSONObject();
                    jSONObject13.putOpt("pos", banner.a);
                    if (banner.b != null) {
                        JSONArray jSONArray3 = new JSONArray();
                        arrayList = arrayList2;
                        int[] iArr = banner.b;
                        i = i2;
                        int length = iArr.length;
                        int i3 = 0;
                        while (i3 < length) {
                            int i4 = i3;
                            jSONArray3.put(iArr[i4]);
                            i3 = i4 + 1;
                        }
                        jSONObject13.putOpt("api", jSONArray3);
                    } else {
                        arrayList = arrayList2;
                        i = i2;
                    }
                    HashSet hashSet = banner.c;
                    jSONObject7 = jSONObject13;
                    if (hashSet.size() > 0) {
                        JSONArray jSONArray4 = new JSONArray();
                        for (Iterator it2 = hashSet.iterator(); it2.hasNext(); it2 = it2) {
                            Format format = (Format) it2.next();
                            format.getClass();
                            JSONObject jSONObject14 = new JSONObject();
                            jSONObject14.putOpt("w", format.a);
                            jSONObject14.putOpt("h", format.b);
                            jSONArray4.put(jSONObject14);
                        }
                        jSONObject13.putOpt("format", jSONArray4);
                        jSONObject7 = jSONObject13;
                    }
                } else {
                    arrayList = arrayList2;
                    i = i2;
                    jSONObject7 = null;
                }
                jSONObject12.putOpt(c.CREATIVE_TYPE_BANNER, jSONObject7);
                JSONObject jSONObject15 = imp.k;
                Video video = imp.g;
                if (video != null) {
                    jSONObject8 = new JSONObject();
                    if (video.a != null) {
                        JSONArray jSONArray5 = new JSONArray();
                        String[] strArr = video.a;
                        int length2 = strArr.length;
                        int i5 = 0;
                        while (i5 < length2) {
                            int i6 = i5;
                            jSONArray5.put(strArr[i6]);
                            i5 = i6 + 1;
                        }
                        jSONObject8.putOpt("mimes", jSONArray5);
                    }
                    jSONObject8.putOpt("minduration", null);
                    jSONObject8.putOpt("maxduration", null);
                    jSONObject8.putOpt("playbackend", video.j);
                    if (video.b != null) {
                        JSONArray jSONArray6 = new JSONArray();
                        int[] iArr2 = video.b;
                        int length3 = iArr2.length;
                        int i7 = 0;
                        while (i7 < length3) {
                            int i8 = i7;
                            jSONArray6.put(iArr2[i8]);
                            i7 = i8 + 1;
                        }
                        jSONObject8.putOpt("protocols", jSONArray6);
                    }
                    jSONObject8.putOpt("w", video.c);
                    jSONObject8.putOpt("h", video.d);
                    jSONObject8.putOpt("startdelay", null);
                    jSONObject8.putOpt("linearity", video.e);
                    jSONObject8.putOpt("minbitrate", null);
                    jSONObject8.putOpt("maxbitrate", null);
                    jSONObject8.putOpt(AdRevenueScheme.PLACEMENT, video.h);
                    jSONObject8.putOpt("plcmt", video.i);
                    if (video.f != null) {
                        JSONArray jSONArray7 = new JSONArray();
                        int[] iArr3 = video.f;
                        int length4 = iArr3.length;
                        int i9 = 0;
                        while (i9 < length4) {
                            int i10 = i9;
                            jSONArray7.put(iArr3[i10]);
                            i9 = i10 + 1;
                        }
                        jSONObject8.putOpt("delivery", jSONArray7);
                    }
                    jSONObject8.putOpt("pos", video.g);
                } else {
                    jSONObject8 = null;
                }
                jSONObject15.putOpt(c.CREATIVE_TYPE_VIDEO, jSONObject8);
                JSONObject jSONObject16 = imp.k;
                Native r8 = imp.h;
                if (r8 != null) {
                    jSONObject9 = new JSONObject();
                    jSONObject9.put("request", r8.a.toString());
                    jSONObject9.put("ver", "1.2");
                    obj = null;
                    jSONObject9.putOpt("ext", null);
                } else {
                    obj = null;
                    jSONObject9 = null;
                }
                jSONObject16.putOpt(c.CREATIVE_TYPE_NATIVE, jSONObject9);
                imp.k.putOpt("pmp", obj);
                JSONObject jSONObject17 = imp.k;
                Ext ext = imp.i;
                jSONObject17.putOpt("ext", ext != null ? ext.a() : null);
                jSONArray2.put(imp.k);
                i2 = i + 1;
                arrayList2 = arrayList;
                obj2 = null;
            }
            jSONObject10.putOpt("imp", jSONArray2);
        }
        jSONObject10.putOpt("id", !TextUtils.isEmpty(this.a) ? this.a : null);
        App app2 = this.b;
        if (app2 != null) {
            jSONObject = new JSONObject();
            jSONObject.putOpt("id", null);
            jSONObject.putOpt("name", app2.a);
            jSONObject.putOpt("bundle", app2.b);
            jSONObject.putOpt("domain", app2.c);
            jSONObject.putOpt("storeurl", app2.d);
            jSONObject.putOpt("ver", app2.e);
            jSONObject.putOpt("privacypolicy", null);
            jSONObject.putOpt("paid", null);
            jSONObject.putOpt("keywords", null);
            Publisher publisher = app2.f;
            if (publisher != null) {
                jSONObject6 = new JSONObject();
                jSONObject6.putOpt("id", publisher.a);
                jSONObject6.putOpt("name", null);
                jSONObject6.putOpt("domain", null);
            } else {
                jSONObject6 = null;
            }
            jSONObject.putOpt(AssociationNames.PUBLISHER, jSONObject6);
            Ext ext2 = app2.g;
            jSONObject.putOpt("ext", ext2 != null ? ext2.a() : null);
        } else {
            jSONObject = null;
        }
        jSONObject10.putOpt("app", jSONObject);
        Device device = this.c;
        if (device != null) {
            jSONObject2 = new JSONObject();
            jSONObject2.putOpt("ua", device.a);
            jSONObject2.putOpt("dnt", null);
            jSONObject2.putOpt("lmt", device.b);
            jSONObject2.putOpt("ip", null);
            jSONObject2.putOpt("ipv6", null);
            jSONObject2.putOpt("devicetype", device.c);
            jSONObject2.putOpt("make", device.d);
            jSONObject2.putOpt(DtbDeviceData.DEVICE_DATA_MODEL_KEY, device.e);
            jSONObject2.putOpt("os", device.f);
            jSONObject2.putOpt("osv", device.g);
            jSONObject2.putOpt("hwv", device.h);
            jSONObject2.putOpt("flashver", null);
            jSONObject2.putOpt("language", device.i);
            jSONObject2.putOpt("carrier", device.j);
            jSONObject2.putOpt("mccmnc", device.k);
            jSONObject2.putOpt("ifa", device.l);
            jSONObject2.putOpt("didsha1", null);
            jSONObject2.putOpt("didmd5", null);
            jSONObject2.putOpt("dpidsha1", null);
            jSONObject2.putOpt("dpidmd5", null);
            jSONObject2.putOpt("h", device.m);
            jSONObject2.putOpt("w", device.n);
            jSONObject2.putOpt("ppi", null);
            jSONObject2.putOpt("js", null);
            jSONObject2.putOpt("connectiontype", device.o);
            jSONObject2.putOpt("pxratio", device.p);
            jSONObject2.putOpt("ext", null);
            jSONObject2.putOpt("geo", null);
        } else {
            jSONObject2 = null;
        }
        jSONObject10.putOpt("device", jSONObject2);
        Regs regs = this.e;
        if (regs != null) {
            jSONObject3 = new JSONObject();
            jSONObject3.putOpt("gpp", regs.b);
            jSONObject3.putOpt("gpp_sid", regs.c);
            jSONObject3.putOpt("coppa", null);
            Ext ext3 = regs.a;
            jSONObject3.putOpt("ext", ext3 != null ? ext3.a() : null);
        } else {
            jSONObject3 = null;
        }
        jSONObject10.putOpt("regs", jSONObject3);
        User user = this.f;
        if (user != null) {
            jSONObject4 = new JSONObject();
            jSONObject4.putOpt("id", null);
            jSONObject4.putOpt("buyeruid", null);
            jSONObject4.putOpt("keywords", user.a);
            jSONObject4.putOpt("customdata", null);
            jSONObject4.putOpt("geo", null);
            Ext ext4 = user.b;
            if (ext4 != null) {
                JSONObject jSONObjectA = ext4.a();
                if (jSONObjectA.length() > 0) {
                    jSONObject4.putOpt("ext", jSONObjectA);
                }
            }
            ArrayList arrayList3 = user.c;
            if (arrayList3.isEmpty()) {
                jSONArray = null;
            } else {
                jSONArray = new JSONArray();
                Iterator it3 = arrayList3.iterator();
                if (it3.hasNext()) {
                    throw a.d(it3);
                }
            }
            if (jSONArray != null) {
                jSONObject4.putOpt("data", jSONArray);
            }
        } else {
            jSONObject4 = null;
        }
        jSONObject10.putOpt("user", jSONObject4);
        Source source = this.g;
        if (source != null) {
            jSONObject5 = new JSONObject();
            jSONObject5.putOpt("tid", !TextUtils.isEmpty(source.a) ? source.a : null);
            Ext ext5 = source.b;
            jSONObject5.putOpt("ext", ext5 != null ? ext5.a() : null);
        } else {
            jSONObject5 = null;
        }
        jSONObject10.putOpt("source", jSONObject5);
        Ext ext6 = this.h;
        jSONObject10.putOpt("ext", ext6 != null ? ext6.a() : null);
        int i11 = PrebidMobile.a;
        jSONObject10.putOpt("test", null);
        HashMap map = TargetingParams.a;
        return jSONObject10;
    }

    public final Regs c() {
        if (this.e == null) {
            this.e = new Regs();
        }
        return this.e;
    }
}
