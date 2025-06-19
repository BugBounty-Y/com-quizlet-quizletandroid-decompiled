package com.onetrust.otpublishers.headless.Public.DataModel;

import java.net.URL;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class OTCustomConfigurator {

    @NotNull
    public static final Companion Companion = new Companion(null);
    public static OTCustomConfigurator b;
    public OTProxyManager a;

    @Metadata
    public static final class Companion {
        private Companion() {
        }

        public static /* synthetic */ void getSharedInstance$annotations() {
        }

        @NotNull
        public final String getProxyDomainURLString(@NotNull OTProxyType proxyType) {
            Intrinsics.checkNotNullParameter(proxyType, "proxyType");
            if (OTCustomConfigurator.b == null) {
                return "";
            }
            OTCustomConfigurator oTCustomConfigurator = OTCustomConfigurator.b;
            Intrinsics.d(oTCustomConfigurator);
            return OTCustomConfigurator.access$getProxyDomainURL(oTCustomConfigurator, proxyType);
        }

        public final OTCustomConfigurator getSharedInstance() {
            if (OTCustomConfigurator.b == null) {
                OTCustomConfigurator.b = new OTCustomConfigurator(null);
            }
            return OTCustomConfigurator.b;
        }

        public final void setupProxyManager(@NotNull OTProxyManager manager) {
            Intrinsics.checkNotNullParameter(manager, "manager");
            if (OTCustomConfigurator.b == null) {
                OTCustomConfigurator.b = new OTCustomConfigurator(null);
            }
            OTCustomConfigurator oTCustomConfigurator = OTCustomConfigurator.b;
            if (oTCustomConfigurator == null) {
                return;
            }
            oTCustomConfigurator.a = manager;
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private OTCustomConfigurator() {
    }

    public static final String access$getProxyDomainURL(OTCustomConfigurator oTCustomConfigurator, OTProxyType oTProxyType) {
        OTProxyManager oTProxyManager = oTCustomConfigurator.a;
        URL proxyDomain = oTProxyManager != null ? oTProxyManager.getProxyDomain(oTProxyType) : null;
        if (proxyDomain == null) {
            return "";
        }
        String string = proxyDomain.toString();
        Intrinsics.checkNotNullExpressionValue(string, "proxyDomainURL.toString()");
        return string.length() == 0 ? "" : string;
    }

    @NotNull
    public static final String getProxyDomainURLString(@NotNull OTProxyType oTProxyType) {
        return Companion.getProxyDomainURLString(oTProxyType);
    }

    public static final OTCustomConfigurator getSharedInstance() {
        return Companion.getSharedInstance();
    }

    public static final void setupProxyManager(@NotNull OTProxyManager oTProxyManager) {
        Companion.setupProxyManager(oTProxyManager);
    }

    public /* synthetic */ OTCustomConfigurator(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }
}
