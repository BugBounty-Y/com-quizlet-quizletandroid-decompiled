package androidx.core.app;

import android.os.Bundle;
import android.widget.RemoteViews;

/* loaded from: classes.dex */
public abstract class F {
    CharSequence mBigContentTitle;
    protected C1034v mBuilder;
    CharSequence mSummaryText;
    boolean mSummaryTextSet = false;

    public void addCompatExtras(Bundle bundle) {
        if (this.mSummaryTextSet) {
            bundle.putCharSequence("android.summaryText", this.mSummaryText);
        }
        CharSequence charSequence = this.mBigContentTitle;
        if (charSequence != null) {
            bundle.putCharSequence("android.title.big", charSequence);
        }
        String className = getClassName();
        if (className != null) {
            bundle.putString("androidx.core.app.extra.COMPAT_TEMPLATE", className);
        }
    }

    public void apply(InterfaceC1024k interfaceC1024k) {
    }

    public String getClassName() {
        return null;
    }

    public RemoteViews makeBigContentView(InterfaceC1024k interfaceC1024k) {
        return null;
    }

    public RemoteViews makeContentView(InterfaceC1024k interfaceC1024k) {
        return null;
    }

    public RemoteViews makeHeadsUpContentView(InterfaceC1024k interfaceC1024k) {
        return null;
    }

    public void setBuilder(C1034v c1034v) {
        if (this.mBuilder != c1034v) {
            this.mBuilder = c1034v;
            if (c1034v != null) {
                c1034v.e(this);
            }
        }
    }
}
