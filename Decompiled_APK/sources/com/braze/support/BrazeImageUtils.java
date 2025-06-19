package com.braze.support;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.util.DisplayMetrics;
import android.widget.ImageView;
import androidx.compose.animation.d0;
import com.braze.AbstractC1484j;
import com.braze.U;
import com.braze.enums.BrazeViewBounds;
import com.braze.managers.J;
import com.braze.storage.F;
import com.braze.support.BrazeLogger;
import java.io.File;
import java.io.InputStream;
import java.net.URL;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public abstract class BrazeImageUtils {
    private static final String TAG = BrazeLogger.INSTANCE.getBrazeLogTag("BrazeImageUtils");

    public static final int calculateInSampleSize(BitmapFactory.Options options, int i, int i2) {
        int i3;
        int i4 = i;
        Intrinsics.checkNotNullParameter(options, "options");
        if (i2 == 0 || i4 == 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new F(12), 14, (Object) null);
            return 1;
        }
        long j = options.outHeight;
        long j2 = options.outWidth;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new U(options, i4, i2, 2), 14, (Object) null);
        H h = new H();
        h.a = 1;
        long j3 = i2;
        if (j > j3 || j2 > i4) {
            long j4 = 2;
            long j5 = j / j4;
            long j6 = j2 / j4;
            while (true) {
                int i5 = h.a;
                long j7 = i5;
                if (j5 / j7 < j3 && j6 / j7 < i4) {
                    i3 = i5;
                    if ((j2 * j) / (i5 * i5) <= 4194304) {
                        break;
                    }
                } else {
                    i3 = i5;
                }
                h.a = i3 * 2;
                i4 = i;
            }
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new r(h, j2, j, 0), 14, (Object) null);
        return h.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String calculateInSampleSize$lambda$4() {
        return "Not sampling on 0 destination width or height";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String calculateInSampleSize$lambda$5(BitmapFactory.Options options, int i, int i2) {
        StringBuilder sb = new StringBuilder("Calculating sample size for source image bounds: (width ");
        sb.append(options.outWidth);
        sb.append(" height ");
        sb.append(options.outHeight);
        sb.append(") and destination image bounds: (width ");
        sb.append(i);
        sb.append(" height ");
        return android.support.v4.media.session.a.q(sb, i2, ')');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String calculateInSampleSize$lambda$6(H h, long j, long j2) {
        return "Using image sample size of " + h.a + ". Image will be scaled to width: " + (j / h.a) + " and height: " + (j2 / h.a);
    }

    private static final Bitmap decodeSampledBitmapFromStream(InputStream inputStream, BitmapFactory.Options options, int i, int i2) {
        options.inSampleSize = calculateInSampleSize(options, i, i2);
        options.inJustDecodeBounds = false;
        return BitmapFactory.decodeStream(inputStream, null, options);
    }

    public static final a getBitmap(Context context, Uri uri, BrazeViewBounds viewBounds) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intrinsics.checkNotNullParameter(viewBounds, "viewBounds");
        Pair<Integer, Integer> destinationHeightAndWidthPixels = getDestinationHeightAndWidthPixels(context, viewBounds);
        int iIntValue = ((Number) destinationHeightAndWidthPixels.a).intValue();
        int iIntValue2 = ((Number) destinationHeightAndWidthPixels.b).intValue();
        if (BrazeFileUtils.isLocalUri(uri)) {
            return new a(getLocalBitmap(uri, iIntValue2, iIntValue), null);
        }
        if (BrazeFileUtils.isRemoteUri(uri)) {
            return getRemoteBitmap(uri, iIntValue2, iIntValue);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.images.h(uri, 2), 12, (Object) null);
        return new a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getBitmap$lambda$7(Uri uri) {
        return android.support.v4.media.session.a.h(uri, "Uri with unknown scheme received. Not getting image. Uri: ");
    }

    public static final BitmapFactory.Options getBitmapMetadataFromStream(InputStream inputStream) {
        Intrinsics.checkNotNullParameter(inputStream, "inputStream");
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeStream(inputStream, null, options);
        return options;
    }

    public static final int getDensityDpi(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return context.getResources().getConfiguration().densityDpi;
    }

    private static final Pair<Integer, Integer> getDestinationHeightAndWidthPixels(Context context, BrazeViewBounds brazeViewBounds) {
        Pair<Integer, Integer> displayHeightAndWidthPixels = getDisplayHeightAndWidthPixels(context);
        int iIntValue = ((Number) displayHeightAndWidthPixels.a).intValue();
        int iIntValue2 = ((Number) displayHeightAndWidthPixels.b).intValue();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new J(iIntValue2, iIntValue, 3), 12, (Object) null);
        if (BrazeViewBounds.NO_BOUNDS == brazeViewBounds) {
            return new Pair<>(Integer.valueOf(iIntValue), Integer.valueOf(iIntValue2));
        }
        int densityDpi = getDensityDpi(context);
        return new Pair<>(Integer.valueOf(Math.min(iIntValue, getPixelsFromDensityAndDp(densityDpi, brazeViewBounds.getHeightDp()))), Integer.valueOf(Math.min(iIntValue2, getPixelsFromDensityAndDp(densityDpi, brazeViewBounds.getWidthDp()))));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getDestinationHeightAndWidthPixels$lambda$23(int i, int i2) {
        return d0.p("Display width: ", i, " and height ", i2);
    }

    public static final Pair<Integer, Integer> getDisplayHeightAndWidthPixels(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        return new Pair<>(Integer.valueOf(displayMetrics.heightPixels), Integer.valueOf(displayMetrics.widthPixels));
    }

    public static final int getDisplayWidthPixels(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return ((Number) getDisplayHeightAndWidthPixels(context).b).intValue();
    }

    public static final int getImageLoaderCacheSize() {
        return Math.max(1024, Math.min((int) Math.min(Runtime.getRuntime().maxMemory() / 8, 2147483647L), 33554432));
    }

    /* JADX WARN: Removed duplicated region for block: B:71:0x014d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:81:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final android.graphics.Bitmap getLocalBitmap(android.net.Uri r23, int r24, int r25) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 360
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.support.BrazeImageUtils.getLocalBitmap(android.net.Uri, int, int):android.graphics.Bitmap");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$10(File file) {
        return "Retrieving image from local path: " + file.getAbsolutePath();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$11() {
        return "Destination bounds unset. Loading entire bitmap into memory.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$12(int i, int i2) {
        return "Sampling bitmap with destination image bounds: (width " + i + " height " + i2 + ')';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$13(Uri uri, BitmapFactory.Options options) {
        StringBuilder sb = new StringBuilder("The bitmap metadata with image uri ");
        sb.append(uri);
        sb.append(" had bounds: (height ");
        sb.append(options.outHeight);
        sb.append(" width ");
        return android.support.v4.media.session.a.r(sb, options.outWidth, "). Returning a bitmap with no sampling.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$14() {
        return "Decoding sampled bitmap";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$15(Exception exc) {
        return "Exception occurred when attempting to retrieve local bitmap. " + exc.getMessage();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$16() {
        return "IOException during closing of bitmap metadata image stream.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$8(Uri uri) {
        return android.support.v4.media.session.a.h(uri, "Local bitmap path is null. URI: ");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalBitmap$lambda$9(Uri uri) {
        return android.support.v4.media.session.a.h(uri, "Local bitmap file does not exist. URI: ");
    }

    public static final int getPixelsFromDensityAndDp(int i, int i2) {
        return Math.abs((i * i2) / 160);
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0163 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:78:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static final com.braze.support.a getRemoteBitmap(android.net.Uri r21, int r22, int r23) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 382
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.support.BrazeImageUtils.getRemoteBitmap(android.net.Uri, int, int):com.braze.support.a");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRemoteBitmap$lambda$17(String str) {
        return AbstractC1484j.a("SDK is in offline mode, not downloading remote bitmap with uri: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRemoteBitmap$lambda$18(int i, URL url) {
        return "HTTP response code was " + i + ". Bitmap with url " + url + " could not be downloaded.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRemoteBitmap$lambda$19(int i, int i2) {
        return "Sampling bitmap with destination image bounds: (height " + i + " width " + i2 + ')';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRemoteBitmap$lambda$20(URL url, BitmapFactory.Options options) {
        StringBuilder sb = new StringBuilder("The bitmap metadata with image url ");
        sb.append(url);
        sb.append(" had bounds: (height ");
        sb.append(options.outHeight);
        sb.append(" width ");
        return android.support.v4.media.session.a.r(sb, options.outWidth, "). Returning a bitmap with no sampling.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRemoteBitmap$lambda$21(String str, Exception exc) {
        return "Exception in image bitmap download for Uri: " + str + ' ' + exc.getMessage();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRemoteBitmap$lambda$22() {
        return "IOException during closing of bitmap metadata download stream.";
    }

    public static final void resizeImageViewToBitmapDimensions(Bitmap bitmap, ImageView imageView) {
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        resizeToBitmapDimensions(imageView, bitmap);
    }

    public static final void resizeToBitmapDimensions(final ImageView imageView, Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(imageView, "<this>");
        if (bitmap == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new F(8), 12, (Object) null);
            return;
        }
        if (bitmap.getWidth() == 0 || bitmap.getHeight() == 0) {
            final int i = 1;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.W, (Throwable) null, false, new Function0() { // from class: com.braze.support.t
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    switch (i) {
                        case 0:
                            return BrazeImageUtils.resizeToBitmapDimensions$lambda$2(imageView);
                        default:
                            return BrazeImageUtils.resizeToBitmapDimensions$lambda$1(imageView);
                    }
                }
            }, 12, (Object) null);
        } else {
            if (imageView.getWidth() == 0 || imageView.getHeight() == 0) {
                final int i2 = 0;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.W, (Throwable) null, false, new Function0() { // from class: com.braze.support.t
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i2) {
                            case 0:
                                return BrazeImageUtils.resizeToBitmapDimensions$lambda$2(imageView);
                            default:
                                return BrazeImageUtils.resizeToBitmapDimensions$lambda$1(imageView);
                        }
                    }
                }, 12, (Object) null);
                return;
            }
            final float width = bitmap.getWidth() / bitmap.getHeight();
            imageView.getLayoutParams().height = (int) (imageView.getWidth() / width);
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.V, (Throwable) null, false, new Function0() { // from class: com.braze.support.q
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    return BrazeImageUtils.resizeToBitmapDimensions$lambda$3(width, imageView);
                }
            }, 12, (Object) null);
            imageView.setLayoutParams(imageView.getLayoutParams());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String resizeToBitmapDimensions$lambda$0() {
        return "Neither source bitmap nor ImageView may be null. Not resizing ImageView";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String resizeToBitmapDimensions$lambda$1(ImageView imageView) {
        return "Bitmap dimensions cannot be 0. Not resizing ImageView " + imageView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String resizeToBitmapDimensions$lambda$2(ImageView imageView) {
        return "ImageView dimensions cannot be 0. Not resizing ImageView " + imageView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String resizeToBitmapDimensions$lambda$3(float f, ImageView imageView) {
        return "Resizing ImageView to aspect ratio " + f + " based on width: " + imageView.getWidth() + " trueWidth: " + imageView.getLayoutParams().width + " height: " + imageView.getLayoutParams().height + " layoutParams: " + imageView.getLayoutParams() + ' ' + imageView;
    }
}
