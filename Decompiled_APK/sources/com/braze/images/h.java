package com.braze.images;

import android.net.Uri;
import com.braze.support.BrazeImageUtils;
import com.braze.ui.BrazeWebViewClient;
import com.braze.ui.actions.UriAction;
import com.braze.ui.actions.brazeactions.BrazeActionParser;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.File;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Uri b;

    public /* synthetic */ h(Uri uri, int i) {
        this.a = i;
        this.b = uri;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return DefaultBrazeImageLoader.shouldSkipCaching$lambda$3(this.b);
            case 1:
                return BrazeImageUtils.getLocalBitmap$lambda$8(this.b);
            case 2:
                return BrazeImageUtils.getBitmap$lambda$7(this.b);
            case 3:
                return BrazeImageUtils.getLocalBitmap$lambda$9(this.b);
            case 4:
                return BrazeWebViewClient.handleUrlOverride$lambda$8(this.b);
            case 5:
                return BrazeWebViewClient.handleQueryAction$lambda$10(this.b);
            case 6:
                return UriAction.openUriWithActionViewFromPush$lambda$6(this.b);
            case 7:
                return BrazeActionParser.getBrazeActionVersionAndJson$lambda$7(this.b);
            case 8:
                return BrazeActionParser.execute$lambda$3(this.b);
            case 9:
                return BrazeActionParser.execute$lambda$4(this.b);
            default:
                String path = this.b.getPath();
                try {
                    int iC = new androidx.exifinterface.media.h(path).c(1, "Orientation");
                    com.facebook.appevents.ml.f.o(iC != 3 ? iC != 6 ? iC != 8 ? 0 : SubsamplingScaleImageView.ORIENTATION_270 : 90 : SubsamplingScaleImageView.ORIENTATION_180, path);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return new File(path);
        }
    }
}
