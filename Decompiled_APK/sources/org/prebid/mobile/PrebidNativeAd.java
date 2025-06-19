package org.prebid.mobile;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.prebid.mobile.ClickTracker;
import org.prebid.mobile.ImpressionTracker;
import org.prebid.mobile.ImpressionTracker.ImpressionListener;
import org.prebid.mobile.NativeData;
import org.prebid.mobile.NativeImage;
import org.prebid.mobile.SharedNetworkManager;
import org.prebid.mobile.http.HTTPGet;
import org.prebid.mobile.http.HTTPResponse;
import org.prebid.mobile.rendering.bidding.events.EventsNotifier;
import org.prebid.mobile.rendering.networking.tracking.ServerConnection;
import org.prebid.mobile.rendering.utils.helpers.ExternalViewerUtils;

/* loaded from: classes3.dex */
public class PrebidNativeAd {
    private static final String TAG = "PrebidNativeAd";
    private ArrayList<ClickTracker> clickTrackers;
    private String clickUrl;
    private ArrayList<String> click_trackers;
    private boolean expired;
    private String impEvent;
    private ArrayList<String> imp_trackers;
    private ArrayList<ImpressionTracker> impressionTrackers;
    private PrebidNativeAdEventListener listener;
    private String privacyUrl;
    private WeakReference<View> registeredView;
    private VisibilityDetector visibilityDetector;
    private String winEvent;
    private boolean impressionIsNotNotified = true;
    private final ArrayList<NativeTitle> titles = new ArrayList<>();
    private final ArrayList<NativeImage> images = new ArrayList<>();
    private final ArrayList<NativeData> dataList = new ArrayList<>();

    public static class CacheExpireListenerImpl {
    }

    private PrebidNativeAd() {
    }

    public static PrebidNativeAd create(String str) throws JSONException {
        String str2;
        int i;
        String str3;
        String str4;
        int iOptInt;
        String str5 = "value";
        String str6 = "data";
        String str7 = "text";
        String str8 = (String) CacheManager.a.remove(str);
        if (TextUtils.isEmpty(str8)) {
            return null;
        }
        try {
            JSONObject jSONObject = new JSONObject(str8);
            JSONObject jSONObject2 = new JSONObject(jSONObject.getString("adm"));
            JSONArray jSONArray = jSONObject2.getJSONArray("assets");
            PrebidNativeAd prebidNativeAd = new PrebidNativeAd();
            CacheManager.b.put(str, new CacheExpireListenerImpl());
            int i2 = 0;
            while (i2 < jSONArray.length()) {
                JSONObject jSONObject3 = jSONArray.getJSONObject(i2);
                JSONArray jSONArray2 = jSONArray;
                if (jSONObject3.has("title")) {
                    i = i2;
                    JSONObject jSONObject4 = jSONObject3.getJSONObject("title");
                    if (jSONObject4.has(str7)) {
                        String string = jSONObject4.getString(str7);
                        if (string.isEmpty()) {
                            str2 = str7;
                        } else {
                            str2 = str7;
                            prebidNativeAd.addTitle(new NativeTitle(string));
                        }
                    } else {
                        str2 = str7;
                        LogUtil.e(5, TAG, "Json title object doesn't have text field");
                    }
                } else {
                    str2 = str7;
                    i = i2;
                }
                if (jSONObject3.has(str6)) {
                    JSONObject jSONObject5 = jSONObject3.getJSONObject(str6);
                    if (jSONObject5.has(str5)) {
                        if (jSONObject5.has(DBUserFields.Names.USER_UPGRADE_TYPE)) {
                            str4 = str6;
                            iOptInt = jSONObject5.optInt(DBUserFields.Names.USER_UPGRADE_TYPE);
                        } else {
                            str4 = str6;
                            iOptInt = 0;
                        }
                        str3 = str5;
                        prebidNativeAd.addData(new NativeData(iOptInt, jSONObject5.getString(str5)));
                    } else {
                        str3 = str5;
                        str4 = str6;
                        LogUtil.e(5, TAG, "Json data object doesn't have type or value field");
                    }
                } else {
                    str3 = str5;
                    str4 = str6;
                }
                if (jSONObject3.has("img")) {
                    JSONObject jSONObject6 = jSONObject3.getJSONObject("img");
                    if (jSONObject6.has(DTBMetricsConfiguration.APSMETRICS_URL)) {
                        prebidNativeAd.addImage(new NativeImage(jSONObject6.has(DBUserFields.Names.USER_UPGRADE_TYPE) ? jSONObject6.optInt(DBUserFields.Names.USER_UPGRADE_TYPE) : 0, jSONObject6.getString(DTBMetricsConfiguration.APSMETRICS_URL)));
                    } else {
                        LogUtil.e(5, TAG, "Json image object doesn't have url or type field");
                    }
                }
                i2 = i + 1;
                jSONArray = jSONArray2;
                str7 = str2;
                str6 = str4;
                str5 = str3;
            }
            if (jSONObject2.has("link")) {
                JSONObject jSONObject7 = jSONObject2.getJSONObject("link");
                if (jSONObject7.has(DTBMetricsConfiguration.APSMETRICS_URL)) {
                    String string2 = jSONObject7.getString(DTBMetricsConfiguration.APSMETRICS_URL);
                    if (string2.contains("{AUCTION_PRICE}") && jSONObject.has("price")) {
                        string2 = string2.replace("{AUCTION_PRICE}", jSONObject.getString("price"));
                    }
                    prebidNativeAd.setClickUrl(string2);
                }
                if (jSONObject7.has("clicktrackers")) {
                    JSONArray jSONArray3 = jSONObject7.getJSONArray("clicktrackers");
                    if (jSONArray3.length() > 0) {
                        prebidNativeAd.click_trackers = new ArrayList<>();
                        for (int i3 = 0; i3 < jSONArray3.length(); i3++) {
                            String string3 = jSONArray3.getString(i3);
                            if (string3.contains("{AUCTION_PRICE}") && jSONObject.has("price")) {
                                string3 = string3.replace("{AUCTION_PRICE}", jSONObject.getString("price"));
                            }
                            prebidNativeAd.click_trackers.add(string3);
                        }
                    }
                }
            }
            if (jSONObject2.has("eventtrackers")) {
                JSONArray jSONArray4 = jSONObject2.getJSONArray("eventtrackers");
                if (jSONArray4.length() > 0) {
                    prebidNativeAd.imp_trackers = new ArrayList<>();
                    for (int i4 = 0; i4 < jSONArray4.length(); i4++) {
                        JSONObject jSONObject8 = jSONArray4.getJSONObject(i4);
                        if (jSONObject8.has(DTBMetricsConfiguration.APSMETRICS_URL)) {
                            String string4 = jSONObject8.getString(DTBMetricsConfiguration.APSMETRICS_URL);
                            if (string4.contains("{AUCTION_PRICE}") && jSONObject.has("price")) {
                                string4 = string4.replace("{AUCTION_PRICE}", jSONObject.getString("price"));
                            }
                            prebidNativeAd.imp_trackers.add(string4);
                        }
                    }
                }
            }
            if (jSONObject2.has("privacy")) {
                prebidNativeAd.setPrivacyUrl(jSONObject2.getString("privacy"));
            }
            parseEvents(jSONObject, prebidNativeAd);
            return prebidNativeAd;
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void createImpressionTrackers(View view) {
        ImpressionTracker impressionTracker;
        ArrayList arrayList = new ArrayList();
        ArrayList<String> arrayList2 = this.imp_trackers;
        if (arrayList2 != null) {
            arrayList.addAll(arrayList2);
        }
        String str = this.impEvent;
        if (str != null) {
            arrayList.add(str);
        }
        this.impressionTrackers = new ArrayList<>();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str2 = (String) it2.next();
            VisibilityDetector visibilityDetector = this.visibilityDetector;
            Context context = view.getContext();
            ImpressionTrackerListener impressionTrackerListener = new ImpressionTrackerListener() { // from class: org.prebid.mobile.PrebidNativeAd.1
                @Override // org.prebid.mobile.ImpressionTrackerListener
                public final void a() {
                    PrebidNativeAd.this.getClass();
                }
            };
            if (visibilityDetector == null) {
                impressionTracker = null;
            } else {
                ImpressionTracker impressionTracker2 = new ImpressionTracker();
                impressionTracker2.c = false;
                impressionTracker2.a = str2;
                impressionTracker2.b = visibilityDetector;
                impressionTracker2.e = impressionTracker2.new ImpressionListener();
                impressionTracker2.d = context.getApplicationContext();
                impressionTracker2.f = impressionTrackerListener;
                ImpressionTracker.ImpressionListener impressionListener = impressionTracker2.e;
                if (impressionListener != null) {
                    visibilityDetector.c.add(impressionListener);
                }
                impressionTracker = impressionTracker2;
            }
            this.impressionTrackers.add(impressionTracker);
        }
    }

    private void fireClickTrackers(Context context) {
        ArrayList<String> arrayList = this.click_trackers;
        if (arrayList == null) {
            return;
        }
        Iterator<String> it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String next = it2.next();
            ClickTracker clickTracker = new ClickTracker();
            clickTracker.b = false;
            clickTracker.a = next;
            Context applicationContext = context.getApplicationContext();
            synchronized (clickTracker) {
                try {
                    if (!clickTracker.b) {
                        SharedNetworkManager sharedNetworkManagerA = SharedNetworkManager.a(applicationContext);
                        if (sharedNetworkManagerA.b(applicationContext)) {
                            new HTTPGet() { // from class: org.prebid.mobile.ClickTracker.1
                                public AnonymousClass1() {
                                }

                                @Override // org.prebid.mobile.http.HTTPGet
                                public final String c() {
                                    return ClickTracker.this.a;
                                }

                                @Override // org.prebid.mobile.http.HTTPGet
                                public final void e(HTTPResponse hTTPResponse) {
                                }
                            }.b();
                        } else {
                            ClickTracker.AnonymousClass2 anonymousClass2 = new ClickTracker.AnonymousClass2();
                            synchronized (sharedNetworkManagerA) {
                                LogUtil.e(3, "PrebidMobile", "SharedNetworkManager adding URL for Network Retry");
                                sharedNetworkManagerA.e = anonymousClass2;
                                sharedNetworkManagerA.a.add(new SharedNetworkManager.UrlObject(next));
                                sharedNetworkManagerA.c(applicationContext);
                            }
                        }
                        clickTracker.b = true;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: handleClick, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public boolean lambda$registerView$1(View view, PrebidNativeAdEventListener prebidNativeAdEventListener) {
        String str = this.clickUrl;
        if (str == null || str.isEmpty() || !openNativeIntent(this.clickUrl, view.getContext())) {
            return false;
        }
        if (prebidNativeAdEventListener != null) {
            prebidNativeAdEventListener.onAdClicked();
        }
        fireClickTrackers(view.getContext());
        return true;
    }

    private void notifyImpressionEvent() {
        if (this.impressionIsNotNotified) {
            this.impressionIsNotNotified = false;
            String str = this.impEvent;
            if (str != null) {
                LogUtil.e(2, "EventsNotifier", "Notify event: ".concat(str));
                ServerConnection.a(str);
            }
        }
    }

    private boolean openNativeIntent(String str, Context context) {
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(str));
        intent.setFlags(268435456);
        try {
            ExternalViewerUtils.c(context, intent);
            return true;
        } catch (ActivityNotFoundException unused) {
            return false;
        }
    }

    private static void parseEvents(JSONObject jSONObject, PrebidNativeAd prebidNativeAd) {
        prebidNativeAd.winEvent = EventsNotifier.a("win", jSONObject);
        prebidNativeAd.impEvent = EventsNotifier.a("imp", jSONObject);
    }

    private void setClickUrl(String str) {
        this.clickUrl = str;
    }

    private void setPrivacyUrl(String str) {
        this.privacyUrl = str;
    }

    public void addData(NativeData nativeData) {
        this.dataList.add(nativeData);
    }

    public void addImage(NativeImage nativeImage) {
        this.images.add(nativeImage);
    }

    public void addTitle(NativeTitle nativeTitle) {
        this.titles.add(nativeTitle);
    }

    @NonNull
    public String getCallToAction() {
        Iterator<NativeData> it2 = this.dataList.iterator();
        while (it2.hasNext()) {
            NativeData next = it2.next();
            if (next.a() == NativeData.Type.c) {
                return next.b;
            }
        }
        return "";
    }

    public String getClickUrl() {
        return this.clickUrl;
    }

    @NonNull
    public ArrayList<NativeData> getDataList() {
        return this.dataList;
    }

    @NonNull
    public String getDescription() {
        Iterator<NativeData> it2 = this.dataList.iterator();
        while (it2.hasNext()) {
            NativeData next = it2.next();
            if (next.a() == NativeData.Type.b) {
                return next.b;
            }
        }
        return "";
    }

    @NonNull
    public String getIconUrl() {
        Iterator<NativeImage> it2 = this.images.iterator();
        while (it2.hasNext()) {
            NativeImage next = it2.next();
            int i = next.a;
            NativeImage.Type type = NativeImage.Type.a;
            if ((i != 1 ? i != 3 ? NativeImage.Type.c : NativeImage.Type.b : type) == type) {
                return next.b;
            }
        }
        return "";
    }

    @NonNull
    public String getImageUrl() {
        Iterator<NativeImage> it2 = this.images.iterator();
        while (it2.hasNext()) {
            NativeImage next = it2.next();
            int i = next.a;
            NativeImage.Type type = NativeImage.Type.b;
            if ((i != 1 ? i != 3 ? NativeImage.Type.c : type : NativeImage.Type.a) == type) {
                return next.b;
            }
        }
        return "";
    }

    @NonNull
    public ArrayList<NativeImage> getImages() {
        return this.images;
    }

    public String getImpEvent() {
        return this.impEvent;
    }

    public String getPrivacyUrl() {
        return this.privacyUrl;
    }

    @NonNull
    public String getSponsoredBy() {
        Iterator<NativeData> it2 = this.dataList.iterator();
        while (it2.hasNext()) {
            NativeData next = it2.next();
            if (next.a() == NativeData.Type.a) {
                return next.b;
            }
        }
        return "";
    }

    @NonNull
    public String getTitle() {
        return !this.titles.isEmpty() ? this.titles.get(0).a : "";
    }

    @NonNull
    public ArrayList<NativeTitle> getTitles() {
        return this.titles;
    }

    public String getWinEvent() {
        return this.winEvent;
    }

    public boolean registerPrebidNativeAdEventListener(PrebidNativeAdEventListener prebidNativeAdEventListener) {
        return true;
    }

    public boolean registerView(View view, List<View> list, PrebidNativeAdEventListener prebidNativeAdEventListener) {
        if (view == null || list == null || list.isEmpty() || this.expired) {
            return false;
        }
        final VisibilityDetector visibilityDetector = new VisibilityDetector();
        visibilityDetector.a = false;
        visibilityDetector.b = new WeakReference(view);
        visibilityDetector.c = new ArrayList();
        if (!visibilityDetector.a) {
            visibilityDetector.a = true;
            visibilityDetector.d = new Runnable() { // from class: org.prebid.mobile.VisibilityDetector.1
                public AnonymousClass1() {
                }

                @Override // java.lang.Runnable
                public final void run() {
                    VisibilityDetector visibilityDetector2 = VisibilityDetector.this;
                    if (visibilityDetector2.c != null) {
                        ArrayList arrayList = new ArrayList();
                        Iterator it2 = visibilityDetector2.c.iterator();
                        while (it2.hasNext()) {
                            arrayList.add((VisibilityListener) it2.next());
                        }
                        View view2 = (View) visibilityDetector2.b.get();
                        if (view2 != null && view2.getVisibility() == 0 && view2.getParent() != null) {
                            Rect rect = new Rect();
                            if (view2.getGlobalVisibleRect(rect)) {
                                int iWidth = rect.width() * rect.height();
                                int width = view2.getWidth() * view2.getHeight();
                                if (width > 0 && iWidth * 100 >= width * 50) {
                                    Iterator it3 = arrayList.iterator();
                                    while (it3.hasNext()) {
                                        ((ImpressionTracker.ImpressionListener) ((VisibilityListener) it3.next())).a(true);
                                    }
                                    return;
                                }
                            }
                        }
                        Iterator it4 = arrayList.iterator();
                        while (it4.hasNext()) {
                            ((ImpressionTracker.ImpressionListener) ((VisibilityListener) it4.next())).a(false);
                        }
                    }
                }
            };
            ScheduledExecutorService scheduledExecutorServiceNewSingleThreadScheduledExecutor = Executors.newSingleThreadScheduledExecutor();
            visibilityDetector.e = scheduledExecutorServiceNewSingleThreadScheduledExecutor;
            scheduledExecutorServiceNewSingleThreadScheduledExecutor.scheduleAtFixedRate(new Runnable() { // from class: org.prebid.mobile.b
                @Override // java.lang.Runnable
                public final void run() {
                    VisibilityDetector visibilityDetector2 = visibilityDetector;
                    View view2 = (View) visibilityDetector2.b.get();
                    if (view2 != null) {
                        view2.post(visibilityDetector2.d);
                    } else {
                        new Handler(Looper.getMainLooper()).post(visibilityDetector2.d);
                        visibilityDetector2.e.shutdownNow();
                    }
                }
            }, 0L, 250L, TimeUnit.MILLISECONDS);
        }
        this.visibilityDetector = visibilityDetector;
        createImpressionTrackers(view);
        this.registeredView = new WeakReference<>(view);
        final int i = 0;
        view.setOnClickListener(new View.OnClickListener(this) { // from class: org.prebid.mobile.a
            public final /* synthetic */ PrebidNativeAd b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        this.b.lambda$registerView$0(null, view2);
                        break;
                    default:
                        this.b.lambda$registerView$1(null, view2);
                        break;
                }
            }
        });
        if (list.size() > 0) {
            for (View view2 : list) {
                if (view2 != null) {
                    final int i2 = 1;
                    view2.setOnClickListener(new View.OnClickListener(this) { // from class: org.prebid.mobile.a
                        public final /* synthetic */ PrebidNativeAd b;

                        {
                            this.b = this;
                        }

                        @Override // android.view.View.OnClickListener
                        public final void onClick(View view22) {
                            switch (i2) {
                                case 0:
                                    this.b.lambda$registerView$0(null, view22);
                                    break;
                                default:
                                    this.b.lambda$registerView$1(null, view22);
                                    break;
                            }
                        }
                    });
                }
            }
        }
        return true;
    }
}
