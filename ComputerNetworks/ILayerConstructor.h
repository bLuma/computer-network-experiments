#ifndef __ILAYERCONSTRUCTOR_H
#define __ILAYERCONSTRUCTOR_H

#include "LayerType.h"
#include "MemBlock.h"

/*
  ILayerConstructor provides interface for construction of packed based on individual layers.
  Layer is able to communicate with upper or lower layer.
*/
class CN_DLLSPEC ILayerConstructor
{
public:
    /// Constructor
    ILayerConstructor() 
    {
        m_upperLayer = NULL;
        m_lowerLayer = NULL;
    }

    /// Sets upper layer
    void setUpperLayer(ILayerConstructor* upperLayer)
    {
        m_upperLayer = upperLayer;
    }

    /// Sets lower layer
    void setLowerLayer(ILayerConstructor* lowerLayer)
    {
        m_lowerLayer = lowerLayer;
    }

    ILayerConstructor* getLowerLayer() 
    {
        return m_lowerLayer;
    }

    ILayerConstructor* getUpperLayer()
    {
        return m_upperLayer;
    }

    /// Is this layer of specified type?
    virtual bool isType(LayerType type) const = 0;
    /// Constructs fragment of data for this layer (and upper layers)
    virtual MemBlock* construct(const MemBlock* upperLayers) = 0;

protected:
    /// Upper layer
    ILayerConstructor* m_upperLayer;
    /// Lower layer
    ILayerConstructor* m_lowerLayer;
};

#endif
