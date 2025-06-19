package com.onetrust.otpublishers.headless.Public.DataModel;

import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.Internal.a;
import com.onetrust.otpublishers.headless.Public.OTBackButtonMode;
import com.onetrust.otpublishers.headless.Public.OTVendorListDismissMode;
import java.util.HashMap;

/* loaded from: classes2.dex */
public class OTConfiguration {
    public final HashMap<String, Typeface> a;
    public final String b;
    public final String c;
    public final String d;
    public final View e;
    public final Drawable f;
    public final Drawable g;
    public final boolean h;

    public static class OTConfigurationBuilder {
        public final HashMap<String, Typeface> a = new HashMap<>();
        public String b;
        public String c;
        public String d;
        public View e;
        public Drawable f;
        public Drawable g;
        public boolean h;

        @NonNull
        public static OTConfigurationBuilder newInstance() {
            return new OTConfigurationBuilder();
        }

        @NonNull
        public OTConfigurationBuilder addOTTypeFace(@NonNull String str, @NonNull Typeface typeface) {
            this.a.put(str, typeface);
            return this;
        }

        @NonNull
        public OTConfiguration build() {
            return new OTConfiguration(this);
        }

        @NonNull
        public OTConfigurationBuilder setBackButton(@NonNull String str) {
            this.b = str;
            return this;
        }

        @NonNull
        public OTConfigurationBuilder setBannerLogo(@NonNull Drawable drawable) {
            this.f = drawable;
            return this;
        }

        @NonNull
        public OTConfigurationBuilder setPCLogo(@NonNull Drawable drawable) {
            this.g = drawable;
            return this;
        }

        @NonNull
        public OTConfigurationBuilder setSyncNotificationView(@NonNull View view) {
            this.e = view;
            return this;
        }

        @NonNull
        public OTConfigurationBuilder setVendorListJourney(@NonNull String str) {
            this.c = str;
            return this;
        }

        @NonNull
        public OTConfigurationBuilder shouldEnableDarkMode(@NonNull String str) {
            this.d = str;
            return this;
        }

        @NonNull
        public OTConfigurationBuilder syncOTUIWithBYOUIMethods(boolean z) {
            this.h = z;
            return this;
        }
    }

    public OTConfiguration(@NonNull OTConfigurationBuilder oTConfigurationBuilder) {
        this.a = oTConfigurationBuilder.a;
        this.b = oTConfigurationBuilder.b;
        this.c = oTConfigurationBuilder.c;
        this.d = oTConfigurationBuilder.d;
        this.e = oTConfigurationBuilder.e;
        this.f = oTConfigurationBuilder.f;
        this.g = oTConfigurationBuilder.g;
        this.h = oTConfigurationBuilder.h;
    }

    public Drawable getBannerLogo() {
        return this.f;
    }

    public String getDarkModeThemeValue() {
        return this.d;
    }

    public Typeface getOtTypeFaceMap(@NonNull String str) {
        if (this.a.containsKey(str)) {
            return this.a.get(str);
        }
        return null;
    }

    public Drawable getPcLogo() {
        return this.g;
    }

    public View getView() {
        return this.e;
    }

    public boolean isBannerBackButtonCloseBanner() {
        if (a.j(this.b)) {
            return false;
        }
        return OTBackButtonMode.DEFAULT_CONSENT_AND_CLOSE_BANNER.equalsIgnoreCase(this.b);
    }

    public boolean isBannerBackButtonDisMissUI() {
        if (a.j(this.b)) {
            return false;
        }
        return OTBackButtonMode.DISMISS_BANNER.equalsIgnoreCase(this.b);
    }

    public boolean isBannerBackButtonDisabled() {
        return (isBannerBackButtonDisMissUI() || isBannerBackButtonCloseBanner()) ? false : true;
    }

    public boolean isShowConfirmMyChoice() {
        if (a.j(this.c)) {
            return false;
        }
        return OTVendorListDismissMode.SHOW_CONFIRM_MY_CHOICE.equalsIgnoreCase(this.c);
    }

    public boolean issSncOTUIWithBYOUIMethodsEnabled() {
        return this.h;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("OTConfig{otTypeFaceMap=");
        sb.append(this.a);
        sb.append("bannerBackButton=");
        sb.append(this.b);
        sb.append("vendorListMode=");
        sb.append(this.c);
        sb.append("darkMode=");
        return d0.r(sb, this.d, '}');
    }

    @NonNull
    public HashMap<String, Typeface> getOtTypeFaceMap() {
        return this.a;
    }
}
