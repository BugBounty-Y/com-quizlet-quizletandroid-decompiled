package com.braze.images;

import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.util.LruCache;
import android.widget.ImageView;
import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1484j;
import com.braze.C1483i;
import com.braze.R$string;
import com.braze.W;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.enums.BrazeViewBounds;
import com.braze.models.cards.Card;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.support.BrazeFileUtils;
import com.braze.support.BrazeImageUtils;
import com.braze.support.BrazeLogger;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes.dex */
public final class DefaultBrazeImageLoader implements IBrazeImageLoader {
    public static final c Companion = new c();
    private static final String TAG = BrazeLogger.getBrazeLogTag((Class<?>) DefaultBrazeImageLoader.class);
    private final ReentrantLock diskCacheLock;
    private a diskLruCache;
    private boolean isDiskCacheStarting;
    private boolean isOffline;
    private final LruCache<String, Bitmap> memoryCache;

    public DefaultBrazeImageLoader(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.diskCacheLock = new ReentrantLock();
        this.isDiskCacheStarting = true;
        this.memoryCache = new b(BrazeImageUtils.getImageLoaderCacheSize());
        initDiskCacheTask(context);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromCache$lambda$13$lambda$12(String str, DefaultBrazeImageLoader defaultBrazeImageLoader) {
        StringBuilder sbY = android.support.v4.media.session.a.y("Got bitmap from mem cache for key ", str, "\nMemory cache stats: ");
        sbY.append(defaultBrazeImageLoader.memoryCache);
        return sbY.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromCache$lambda$15$lambda$14(String str) {
        return AbstractC1484j.a("Got bitmap from disk cache for key ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromCache$lambda$16(String str) {
        return AbstractC1484j.a("No cache hit for bitmap: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromDiskCache$lambda$19$lambda$17(String str) {
        return AbstractC1484j.a("Disk cache still starting. Cannot retrieve key from disk cache: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromDiskCache$lambda$19$lambda$18(String str) {
        return AbstractC1484j.a("Getting bitmap from disk cache for key: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromUrl$lambda$10() {
        return "Cache is currently in offline mode. Not downloading bitmap.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromUrl$lambda$11(String str) {
        return AbstractC1484j.a("Failed to get bitmap from url. Url: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmapFromUrl$lambda$8() {
        return "Cannot retrieve bitmap with blank image url";
    }

    private final void initDiskCacheTask(Context context) {
        E.A(BrazeCoroutineScope.INSTANCE, null, null, new d(context, this, null), 3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String putBitmapIntoCache$lambda$20(String str) {
        return AbstractC1484j.a("Adding bitmap to mem cache for key ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String putBitmapIntoCache$lambda$21(String str) {
        return AbstractC1484j.a("Skipping disk cache for key: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String putBitmapIntoCache$lambda$23$lambda$22(String str) {
        return AbstractC1484j.a("Adding bitmap to disk cache for key ", str);
    }

    private final Bitmap putBitmapIntoMemCache(String str, Bitmap bitmap) {
        return this.memoryCache.put(str, bitmap);
    }

    private final void renderUrlIntoView(Context context, String str, ImageView imageView, BrazeViewBounds brazeViewBounds) {
        if (StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.h(19), 7, (Object) null);
            return;
        }
        try {
            renderUrlIntoViewTask$android_sdk_base_release(context, imageView, brazeViewBounds, str);
        } catch (Throwable th) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, th, false, (Function0) new W(str, 20), 4, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String renderUrlIntoView$lambda$1() {
        return "Cannot retrieve bitmap with a blank image url";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String renderUrlIntoView$lambda$2(String str) {
        return AbstractC1484j.a("Failed to render url into view. Url: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setOffline$lambda$0(boolean z) {
        return "DefaultBrazeImageLoader outbound network requests are now ".concat(z ? "disabled" : "enabled");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String shouldSkipCaching$lambda$3(Uri uri) {
        return android.support.v4.media.session.a.h(uri, "Image url specifies that it should not be cached. Not caching ");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String shouldSkipCaching$lambda$7$lambda$6(Map.Entry entry, Uri uri) {
        return "Headers specify that this image should not be cached (" + entry + "). Not caching " + uri;
    }

    public final com.braze.support.a downloadBitmapFromUrl(Context context, Uri imageUri, BrazeViewBounds brazeViewBounds) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageUri, "imageUri");
        if (brazeViewBounds == null) {
            brazeViewBounds = BrazeViewBounds.NO_BOUNDS;
        }
        return BrazeImageUtils.getBitmap(context, imageUri, brazeViewBounds);
    }

    public final Bitmap getBitmapFromCache(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Bitmap bitmap = this.memoryCache.get(key);
        if (bitmap != null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C1277j(6, key, this), 6, (Object) null);
            return bitmap;
        }
        Bitmap bitmapFromDiskCache = getBitmapFromDiskCache(key);
        if (bitmapFromDiskCache == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new W(key, 23), 7, (Object) null);
            return null;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new W(key, 22), 6, (Object) null);
        putBitmapIntoMemCache(key, bitmapFromDiskCache);
        return bitmapFromDiskCache;
    }

    public final Bitmap getBitmapFromDiskCache(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        ReentrantLock reentrantLock = this.diskCacheLock;
        reentrantLock.lock();
        try {
            if (this.isDiskCacheStarting) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new W(key, 18), 6, (Object) null);
            } else {
                a aVar = this.diskLruCache;
                if (aVar == null) {
                    Intrinsics.m("diskLruCache");
                    throw null;
                }
                if (aVar.a(key)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new W(key, 19), 6, (Object) null);
                    a aVar2 = this.diskLruCache;
                    if (aVar2 == null) {
                        Intrinsics.m("diskLruCache");
                        throw null;
                    }
                    Bitmap bitmapB = aVar2.b(key);
                    reentrantLock.unlock();
                    return bitmapB;
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
            return null;
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final Bitmap getBitmapFromMemCache(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.memoryCache.get(key);
    }

    public final Bitmap getBitmapFromUrl(Context context, String imageUrl, BrazeViewBounds brazeViewBounds) {
        Bitmap bitmapFromCache;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        if (StringsKt.O(imageUrl)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.h(20), 7, (Object) null);
            return null;
        }
        try {
            bitmapFromCache = getBitmapFromCache(imageUrl);
        } catch (Throwable th) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, th, false, (Function0) new W(imageUrl, 21), 4, (Object) null);
        }
        if (bitmapFromCache != null) {
            return bitmapFromCache;
        }
        if (this.isOffline) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.events.h(21), 7, (Object) null);
            return null;
        }
        Uri uri = Uri.parse(imageUrl);
        Intrinsics.d(uri);
        com.braze.support.a aVarDownloadBitmapFromUrl = downloadBitmapFromUrl(context, uri, brazeViewBounds);
        if (aVarDownloadBitmapFromUrl.a != null) {
            if (!shouldSkipCaching(uri, aVarDownloadBitmapFromUrl.b)) {
                putBitmapIntoCache(imageUrl, aVarDownloadBitmapFromUrl.a, BrazeFileUtils.isLocalUri(uri));
            }
            return aVarDownloadBitmapFromUrl.a;
        }
        return null;
    }

    @Override // com.braze.images.IBrazeImageLoader
    public Bitmap getInAppMessageBitmapFromUrl(Context context, IInAppMessage inAppMessage, String imageUrl, BrazeViewBounds brazeViewBounds) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        return getBitmapFromUrl(context, imageUrl, brazeViewBounds);
    }

    @Override // com.braze.images.IBrazeImageLoader
    public Bitmap getPushBitmapFromUrl(Context context, Bundle bundle, String imageUrl, BrazeViewBounds brazeViewBounds) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        return getBitmapFromUrl(context, imageUrl, brazeViewBounds);
    }

    public final void putBitmapIntoCache(String key, Bitmap bitmap, boolean z) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(bitmap, "bitmap");
        if (getBitmapFromMemCache(key) == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new W(key, 24), 7, (Object) null);
            this.memoryCache.put(key, bitmap);
        }
        if (z) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new W(key, 25), 7, (Object) null);
            return;
        }
        ReentrantLock reentrantLock = this.diskCacheLock;
        reentrantLock.lock();
        try {
            if (!this.isDiskCacheStarting) {
                a aVar = this.diskLruCache;
                if (aVar == null) {
                    Intrinsics.m("diskLruCache");
                    throw null;
                }
                if (!aVar.a(key)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new W(key, 17), 7, (Object) null);
                    a aVar2 = this.diskLruCache;
                    if (aVar2 == null) {
                        Intrinsics.m("diskLruCache");
                        throw null;
                    }
                    aVar2.a(key, bitmap);
                }
            }
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    @Override // com.braze.images.IBrazeImageLoader
    public void renderUrlIntoCardView(Context context, Card card, String imageUrl, ImageView imageView, BrazeViewBounds brazeViewBounds) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(card, "card");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        renderUrlIntoView(context, imageUrl, imageView, brazeViewBounds);
    }

    @Override // com.braze.images.IBrazeImageLoader
    public void renderUrlIntoInAppMessageView(Context context, IInAppMessage inAppMessage, String imageUrl, ImageView imageView, BrazeViewBounds brazeViewBounds) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(inAppMessage, "inAppMessage");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        renderUrlIntoView(context, imageUrl, imageView, brazeViewBounds);
    }

    public final void renderUrlIntoViewTask$android_sdk_base_release(Context context, ImageView imageView, BrazeViewBounds brazeViewBounds, String imageUrl) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        imageView.setTag(R$string.com_braze_image_lru_cache_image_url_key, imageUrl);
        E.A(BrazeCoroutineScope.INSTANCE, null, null, new g(this, context, imageUrl, brazeViewBounds, imageView, null), 3);
    }

    @Override // com.braze.images.IBrazeImageLoader
    public void setOffline(boolean z) {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1483i(z, 4), 6, (Object) null);
        this.isOffline = z;
    }

    public final boolean shouldSkipCaching(Uri imageUri, Map<String, ? extends List<String>> map) {
        Intrinsics.checkNotNullParameter(imageUri, "imageUri");
        if (!imageUri.getBooleanQueryParameter("cache", true)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(imageUri, 0), 7, (Object) null);
            return true;
        }
        if (map == null) {
            return false;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry<String, ? extends List<String>> entry : map.entrySet()) {
            if (D.l(entry.getKey(), "cache-control", true)) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        for (Map.Entry entry2 : linkedHashMap.entrySet()) {
            Iterable<String> iterable = (Iterable) entry2.getValue();
            if (!(iterable instanceof Collection) || !((Collection) iterable).isEmpty()) {
                for (String str : iterable) {
                    if (StringsKt.G(str, "no-cache", true) || StringsKt.G(str, "max-age=0", true)) {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1277j(5, entry2, imageUri), 7, (Object) null);
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
