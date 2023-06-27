//
//  IBKPexception.hpp
//  libidevicebackup
//
//  Created by erd on 25.06.21.
//

#ifndef IBKPexception_hpp
#define IBKPexception_hpp

#include <libgeneral/macros.h>
#include <libgeneral/exception.hpp>


namespace tihmstar {
    class IBKPexception : public tihmstar::exception{
        using exception::exception;
    };

//custom exceptions for makeing it easy to catch
    class IBKPPasscodeValueAlreadySet : public IBKPexception{
        using IBKPexception::IBKPexception;
    };

    class IBKPexceptionUser_callback_aborted : public IBKPexception{
        using IBKPexception::IBKPexception;
    };

    class IBKPexceptionUser_failed_to_start_backup : public IBKPexception{
        using IBKPexception::IBKPexception;
    };

};
#endif /* IBKPexception_hpp */
