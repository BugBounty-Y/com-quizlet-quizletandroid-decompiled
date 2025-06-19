package com.quizlet.db.data.orm;

import com.google.common.collect.C;
import com.google.common.collect.C3921d;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.net.ModelApiNameMapping;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.builder.a;
import org.apache.commons.lang3.builder.b;
import org.apache.commons.lang3.e;

/* loaded from: classes2.dex */
public class Include implements Cloneable {
    private static final String INCLUDE_KEY_POSTFIX = "[]";
    private static final String INCLUDE_KEY_SEGMENT_TEMPLATE = "[%s]";
    private static final String INCLUDE_STRING_PREFIX = "include";
    public final List a;

    public Include(List list) {
        this.a = list;
        if (list.size() == 0) {
            throw new IllegalArgumentException("At least 1 relationship must be specified");
        }
        int i = 0;
        while (i < list.size() - 1) {
            Relationship relationship = (Relationship) list.get(i);
            i++;
            Relationship relationship2 = (Relationship) list.get(i);
            if (!relationship.getToModelTypes().contains(relationship2.getFromModelType())) {
                throw new IllegalArgumentException("Relationship " + relationship2 + " does not correspond to " + relationship);
            }
        }
    }

    public static boolean b(DBModel dBModel, List list) {
        if (dBModel == null) {
            return false;
        }
        if (list.size() == 0) {
            return true;
        }
        Relationship relationship = (Relationship) list.get(0);
        if (relationship.isRequired()) {
            return b(relationship.getModel(dBModel), list.subList(1, list.size()));
        }
        return true;
    }

    public final Object clone() {
        return new Include(this.a);
    }

    public final boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Include)) {
            return false;
        }
        a aVar = new a();
        aVar.a(this.a, ((Include) obj).a);
        return aVar.a;
    }

    public String getJsonKey() {
        C c = ModelApiNameMapping.a;
        List list = this.a;
        String str = (String) c.get(((Relationship) list.get(0)).getFromModelType());
        StringBuilder sb = new StringBuilder("include");
        sb.append("[" + str + "]");
        if (list.size() > 1) {
            sb.append(e.e("", new C3921d(list.subList(0, list.size() - 1), new com.quizlet.baserecyclerview.decoration.a(5))));
        }
        sb.append(INCLUDE_KEY_POSTFIX);
        return sb.toString();
    }

    public String getJsonValue() {
        return ((Relationship) this.a.get(r0.size() - 1)).getApiAssociationName();
    }

    public List<Relationship> getRelationships() {
        return this.a;
    }

    public final int hashCode() {
        b bVar = new b(7243, 2083);
        bVar.b(this.a);
        return bVar.b;
    }

    public Include(Relationship... relationshipArr) {
        this(Arrays.asList(relationshipArr));
    }
}
