package com.comscore;

import com.comscore.ClientConfiguration;

/* loaded from: classes.dex */
public class PublisherConfiguration extends ClientConfiguration {
    private PublisherUniqueDeviceIdListener d;

    public static class Builder extends ClientConfiguration.Builder<Builder, PublisherConfiguration> {
        private PublisherUniqueDeviceIdListener a;

        public Builder() {
        }

        @Override // com.comscore.ClientConfiguration.Builder
        /* renamed from: b, reason: merged with bridge method [inline-methods] */
        public Builder a() {
            return new Builder(this);
        }

        public Builder publisherId(String str) {
            setClientId(str);
            return this;
        }

        public Builder publisherUniqueDeviceIdListener(PublisherUniqueDeviceIdListener publisherUniqueDeviceIdListener) {
            this.a = publisherUniqueDeviceIdListener;
            return this;
        }

        @Override // com.comscore.ClientConfiguration.Builder
        public Builder self() {
            return this;
        }

        private Builder(Builder builder) {
            super(builder);
        }

        @Override // com.comscore.ClientConfiguration.Builder
        public PublisherConfiguration build() {
            return new PublisherConfiguration(this, this.a, 0);
        }
    }

    public /* synthetic */ PublisherConfiguration(Builder builder, PublisherUniqueDeviceIdListener publisherUniqueDeviceIdListener, int i) {
        this(builder, publisherUniqueDeviceIdListener);
    }

    private static native void destroyCppInstanceNative(long j, PublisherUniqueDeviceIdListener publisherUniqueDeviceIdListener);

    private static native String getPublisherIdNative(long j);

    private static native long newCppInstanceNative(Builder builder, PublisherUniqueDeviceIdListener publisherUniqueDeviceIdListener);

    @Override // com.comscore.util.cpp.CppJavaBinder
    public void destroyCppObject() {
        destroyCppInstanceNative(this.b, this.d);
    }

    public String getPublisherId() {
        try {
            return getPublisherIdNative(this.b);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
            return null;
        }
    }

    public PublisherConfiguration(long j) {
        this.b = j;
    }

    private PublisherConfiguration(Builder builder, PublisherUniqueDeviceIdListener publisherUniqueDeviceIdListener) {
        super(builder);
        this.d = publisherUniqueDeviceIdListener;
        try {
            this.b = newCppInstanceNative(builder, publisherUniqueDeviceIdListener);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
        }
    }
}
