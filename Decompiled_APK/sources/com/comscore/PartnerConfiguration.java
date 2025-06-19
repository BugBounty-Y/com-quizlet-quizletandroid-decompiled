package com.comscore;

import com.comscore.ClientConfiguration;

/* loaded from: classes.dex */
public class PartnerConfiguration extends ClientConfiguration {

    public static class Builder extends ClientConfiguration.Builder<Builder, PartnerConfiguration> {
        protected String externalClientId;

        public Builder() {
        }

        @Override // com.comscore.ClientConfiguration.Builder
        /* renamed from: b, reason: merged with bridge method [inline-methods] */
        public Builder a() {
            return new Builder(this);
        }

        public Builder externalClientId(String str) {
            this.externalClientId = str;
            return this;
        }

        public Builder partnerId(String str) {
            setClientId(str);
            return this;
        }

        @Override // com.comscore.ClientConfiguration.Builder
        public Builder self() {
            return this;
        }

        private Builder(Builder builder) {
            super(builder);
            this.externalClientId = builder.externalClientId;
        }

        @Override // com.comscore.ClientConfiguration.Builder
        public PartnerConfiguration build() {
            return new PartnerConfiguration(this, 0);
        }
    }

    public /* synthetic */ PartnerConfiguration(Builder builder, int i) {
        this(builder);
    }

    private static native void destroyCppInstanceNative(long j);

    private static native String getExternalClientIdNative(long j);

    private static native String getPartnerIdNative(long j);

    private static native long newCppInstanceNative(Builder builder);

    @Override // com.comscore.util.cpp.CppJavaBinder
    public void destroyCppObject() {
        destroyCppInstanceNative(this.b);
    }

    public String getExternalClientId() {
        try {
            return getExternalClientIdNative(this.b);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
            return null;
        }
    }

    public String getPartnerId() {
        try {
            return getPartnerIdNative(this.b);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
            return null;
        }
    }

    public PartnerConfiguration(long j) {
        this.b = j;
    }

    private PartnerConfiguration(Builder builder) {
        super(builder);
        try {
            this.b = newCppInstanceNative(builder);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
        }
    }
}
