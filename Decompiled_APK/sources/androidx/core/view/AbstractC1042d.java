package androidx.core.view;

import android.content.ClipData;
import android.content.pm.ApkChecksum;
import android.media.metrics.MediaMetricsManager;
import android.view.ContentInfo;

/* renamed from: androidx.core.view.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract /* synthetic */ class AbstractC1042d {
    public static /* bridge */ /* synthetic */ ApkChecksum e(Object obj) {
        return (ApkChecksum) obj;
    }

    public static /* bridge */ /* synthetic */ MediaMetricsManager i(Object obj) {
        return (MediaMetricsManager) obj;
    }

    public static /* synthetic */ ContentInfo.Builder p(ClipData clipData, int i) {
        return new ContentInfo.Builder(clipData, i);
    }

    public static /* bridge */ /* synthetic */ ContentInfo q(Object obj) {
        return (ContentInfo) obj;
    }
}
