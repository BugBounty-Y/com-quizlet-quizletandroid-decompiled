package com.quizlet.db.data.models.identity;

import com.j256.ormlite.stmt.Where;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.orm.Relationship;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.lang3.e;

/* loaded from: classes2.dex */
public class ModelIdentityCollection<M extends DBModel> extends ArrayList<ModelIdentity<M>> {
    public ModelIdentityCollection() {
    }

    public static <N extends DBModel> ModelIdentityCollection<N> identitiesForModels(List<N> list) {
        ModelIdentityCollection<N> modelIdentityCollection = new ModelIdentityCollection<>();
        Iterator<N> it2 = list.iterator();
        while (it2.hasNext()) {
            modelIdentityCollection.add((ModelIdentity) it2.next().getIdentity());
        }
        return modelIdentityCollection;
    }

    public static <F extends DBModel, T extends DBModel> ModelIdentityCollection<F> identitiesForRelatedModels(List<F> list, Relationship<F, T> relationship) {
        ModelIdentityCollection<F> modelIdentityCollection = new ModelIdentityCollection<>();
        Iterator<F> it2 = list.iterator();
        while (it2.hasNext()) {
            ModelIdentity<T> toModelIdentity = relationship.getToModelIdentity(it2.next());
            if (toModelIdentity != null) {
                modelIdentityCollection.add((ModelIdentity) toModelIdentity);
            }
        }
        return modelIdentityCollection;
    }

    public ModelType<M> getModelType() {
        if (size() > 0) {
            return get(0).getModelType();
        }
        return null;
    }

    public String urlString() {
        ArrayList arrayList = new ArrayList(size());
        Iterator<ModelIdentity<M>> it2 = iterator();
        while (it2.hasNext()) {
            String strUrlString = ((ModelIdentity) it2.next()).urlString();
            if (strUrlString != null) {
                arrayList.add(strUrlString);
            }
        }
        return e.e(",", arrayList);
    }

    public Where whereIn(Where where) throws SQLException {
        int i = 0;
        if (size() > 0 && get(0).getIdentityFields().size() == 1) {
            HashSet hashSet = new HashSet(size());
            Iterator<ModelIdentity<M>> it2 = iterator();
            while (it2.hasNext()) {
                hashSet.add(((ModelIdentity) it2.next()).getSingleFieldIdentityValue());
            }
            where.in(get(0).getIdentityFields().iterator().next().getDatabaseColumnName(), hashSet);
            return where;
        }
        Iterator<ModelIdentity<M>> it3 = iterator();
        while (it3.hasNext()) {
            ((ModelIdentity) it3.next()).whereEq(where);
            i++;
        }
        if (i > 0) {
            where.or(i);
        }
        return where;
    }

    public ModelIdentityCollection(ModelIdentity<M> modelIdentity) {
        add((ModelIdentity) modelIdentity);
    }

    @Override // java.util.ArrayList, java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public boolean add(ModelIdentity<M> modelIdentity) {
        if (modelIdentity != null) {
            return super.add((ModelIdentityCollection<M>) modelIdentity);
        }
        throw new IllegalArgumentException("Cannot add null modelIdentity");
    }

    public ModelIdentityCollection(Collection<ModelIdentity<M>> collection) {
        addAll(collection);
    }
}
