package com.onetrust.otpublishers.headless.Public.DataModel;

import androidx.annotation.Keep;
import java.net.URL;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public abstract class OTProxyType {

    @Keep
    @Metadata
    public static final class AgeGateLogo extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public AgeGateLogo(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ AgeGateLogo copy$default(AgeGateLogo ageGateLogo, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = ageGateLogo.url;
            }
            return ageGateLogo.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final AgeGateLogo copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new AgeGateLogo(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof AgeGateLogo) && Intrinsics.b(this.url, ((AgeGateLogo) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "AgeGateLogo(url=" + this.url + ')';
        }
    }

    @Keep
    @Metadata
    public static final class BannerLogo extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public BannerLogo(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ BannerLogo copy$default(BannerLogo bannerLogo, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = bannerLogo.url;
            }
            return bannerLogo.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final BannerLogo copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new BannerLogo(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof BannerLogo) && Intrinsics.b(this.url, ((BannerLogo) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "BannerLogo(url=" + this.url + ')';
        }
    }

    @Keep
    @Metadata
    public static final class GoogleVendors extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public GoogleVendors(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ GoogleVendors copy$default(GoogleVendors googleVendors, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = googleVendors.url;
            }
            return googleVendors.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final GoogleVendors copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new GoogleVendors(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof GoogleVendors) && Intrinsics.b(this.url, ((GoogleVendors) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "GoogleVendors(url=" + this.url + ')';
        }
    }

    @Keep
    @Metadata
    public static final class IABVendors extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public IABVendors(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ IABVendors copy$default(IABVendors iABVendors, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = iABVendors.url;
            }
            return iABVendors.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final IABVendors copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new IABVendors(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof IABVendors) && Intrinsics.b(this.url, ((IABVendors) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "IABVendors(url=" + this.url + ')';
        }
    }

    @Keep
    @Metadata
    public static final class LogConsent extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public LogConsent(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ LogConsent copy$default(LogConsent logConsent, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = logConsent.url;
            }
            return logConsent.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final LogConsent copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new LogConsent(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof LogConsent) && Intrinsics.b(this.url, ((LogConsent) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "LogConsent(url=" + this.url + ')';
        }
    }

    @Keep
    @Metadata
    public static final class PCLogo extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public PCLogo(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ PCLogo copy$default(PCLogo pCLogo, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = pCLogo.url;
            }
            return pCLogo.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final PCLogo copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new PCLogo(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof PCLogo) && Intrinsics.b(this.url, ((PCLogo) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "PCLogo(url=" + this.url + ')';
        }
    }

    @Keep
    @Metadata
    public static final class SDKDataDownload extends OTProxyType {

        @NotNull
        public final URL url;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public SDKDataDownload(@NotNull URL url) {
            super(null);
            Intrinsics.checkNotNullParameter(url, "url");
            this.url = url;
        }

        public static /* synthetic */ SDKDataDownload copy$default(SDKDataDownload sDKDataDownload, URL url, int i, Object obj) {
            if ((i & 1) != 0) {
                url = sDKDataDownload.url;
            }
            return sDKDataDownload.copy(url);
        }

        @NotNull
        public final URL component1() {
            return this.url;
        }

        @NotNull
        public final SDKDataDownload copy(@NotNull URL url) {
            Intrinsics.checkNotNullParameter(url, "url");
            return new SDKDataDownload(url);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof SDKDataDownload) && Intrinsics.b(this.url, ((SDKDataDownload) obj).url);
        }

        public int hashCode() {
            return this.url.hashCode();
        }

        @NotNull
        public String toString() {
            return "SDKDataDownload(url=" + this.url + ')';
        }
    }

    private OTProxyType() {
    }

    public /* synthetic */ OTProxyType(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }
}
